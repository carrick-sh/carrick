//! /proc/self/status Pid/Tgid agree with getpid()/gettid() for a
//! single-threaded process (LTP gettid01). carrick hardcoded "Pid: 1" in the
//! synthetic /proc/self/status while getpid()/gettid() returned a different
//! value. Asserts equality (the run-varying pid value itself is never printed),
//! so it diffs line-exact carrick-vs-Linux.

fn main() {
    unsafe {
        let getpid = libc::getpid() as i64;
        let gettid = libc::syscall(libc::SYS_gettid) as i64;
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let field = |key: &str| -> i64 {
            status
                .lines()
                .find_map(|l| l.strip_prefix(key).map(|v| v.trim().parse::<i64>().unwrap_or(-1)))
                .unwrap_or(-2)
        };
        println!("gettid_eq_getpid={}", gettid == getpid);
        println!("proc_pid_eq_getpid={}", field("Pid:") == getpid);
        println!("proc_tgid_eq_getpid={}", field("Tgid:") == getpid);
    }
}
