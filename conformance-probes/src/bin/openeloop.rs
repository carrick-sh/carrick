//! Opening a symlink that forms a cycle must fail with ELOOP (libuv fs_file_loop).
//! Carrick's open() followed the final symlink via canonicalize_following but
//! SWALLOWED its Err — including the ELOOP a cycle produces — so it returned a
//! descriptor instead of -ELOOP.
//!
//!  * open_loop_is_eloop: open() of a 2-symlink cycle (a->b->a) returns
//!    -1/ELOOP, matching Linux.
//!  * open_missing_still_enoent: open() (no O_CREAT) of a normal missing path
//!    still returns ENOENT (guards that the fix only propagates ELOOP, not every
//!    canonicalize error).

const A: &[u8] = b"/tmp/eloop_a\0";
const B: &[u8] = b"/tmp/eloop_b\0";
const MISS: &[u8] = b"/tmp/eloop_missing\0";

fn main() {
    unsafe { run() }
}

unsafe fn run() {
    libc::unlink(A.as_ptr().cast());
    libc::unlink(B.as_ptr().cast());
    // a -> b, b -> a : a symlink cycle.
    let s1 = libc::symlink(B.as_ptr().cast(), A.as_ptr().cast());
    let s2 = libc::symlink(A.as_ptr().cast(), B.as_ptr().cast());
    if s1 != 0 || s2 != 0 {
        println!("setup=false symlink_rc={s1},{s2}");
        return;
    }

    let fd = libc::open(A.as_ptr().cast(), libc::O_RDONLY);
    let e = if fd < 0 { *libc::__errno_location() } else { 0 };
    let open_loop_is_eloop = fd < 0 && e == libc::ELOOP;

    // A normal missing path (no O_CREAT) must still be ENOENT, not ELOOP.
    let fd2 = libc::open(MISS.as_ptr().cast(), libc::O_RDONLY);
    let e2 = if fd2 < 0 {
        *libc::__errno_location()
    } else {
        0
    };
    let open_missing_still_enoent = fd2 < 0 && e2 == libc::ENOENT;

    println!("open_loop_fd={fd} open_loop_errno={e}");
    println!("open_loop_is_eloop={open_loop_is_eloop}");
    println!("open_missing_still_enoent={open_missing_still_enoent}");

    if fd >= 0 {
        libc::close(fd);
    }
    if fd2 >= 0 {
        libc::close(fd2);
    }
    libc::unlink(A.as_ptr().cast());
    libc::unlink(B.as_ptr().cast());
}
