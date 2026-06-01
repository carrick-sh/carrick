//! dup(2) returns the LOWEST-numbered unused descriptor (incl. 0 when stdin is
//! closed), NOT a freed higher fd. Carrick floored dup's target at 3, so with
//! the pipe write-end freed and stdin closed, `dup(read_end)` returned that
//! freed fd (>=3) instead of 0 — leaving fd 0 closed, which crashed libuv's
//! uv_pipe_open(loop, 0) path (test pipe_close_stdout_read_stdin).
//!
//!  * dup_is_zero: after close(write_end) + close(0), dup(read_end) == 0.

fn main() {
    unsafe { run() }
}

unsafe fn run() {
    let mut fd = [0i32; 2];
    if libc::pipe(fd.as_mut_ptr()) != 0 {
        println!("setup=false");
        return;
    }
    // Free a non-stdio fd (the write end) AND close stdin. The lowest unused
    // fd is now 0; a correct dup must pick it, not the freed write-end fd.
    libc::close(fd[1]);
    libc::close(0);
    let d = libc::dup(fd[0]);
    let dup_is_zero = d == 0;

    // fd 1 (stdout) is still open, so this prints.
    println!("dup_after_close0={d}");
    println!("dup_is_zero={dup_is_zero}");

    if d > 0 {
        libc::close(d);
    }
    libc::close(fd[0]);
}
