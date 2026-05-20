//! Process/identity probe. Exercises getpid/getppid, the uid/gid family,
//! umask, uname, sysinfo, scheduling, rlimits and prctl, printing one
//! labelled line per observation. The conformance harness runs this identical
//! static binary under carrick and real Linux and diffs line by line — a
//! divergent line names the exact failing syscall.
//!
//! Deterministic only: no pids, timestamps, addresses, or memory sizes are
//! ever printed (those are reduced to booleans/relationships).

use std::ffi::CStr;

fn main() {
    // getpid()/getppid(): never print the values (non-deterministic).
    // Print only stable relationships.
    let pid = unsafe { libc::getpid() };
    let ppid = unsafe { libc::getppid() };
    println!("pid_positive={}", pid > 0);
    println!("ppid_differs={}", ppid != pid);

    // uid/gid family — carrick runs guest as root, so all 0.
    println!("getuid={}", unsafe { libc::getuid() });
    println!("geteuid={}", unsafe { libc::geteuid() });
    println!("getgid={}", unsafe { libc::getgid() });
    println!("getegid={}", unsafe { libc::getegid() });

    // getgroups: count + whether group 0 is present.
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n < 0 {
        println!("getgroups=ERR:{}", std::io::Error::last_os_error().raw_os_error().unwrap_or(-1));
    } else {
        let mut groups = vec![0 as libc::gid_t; n as usize];
        let got = unsafe { libc::getgroups(n, groups.as_mut_ptr()) };
        if got < 0 {
            println!("getgroups=ERR:{}", std::io::Error::last_os_error().raw_os_error().unwrap_or(-1));
        } else {
            groups.truncate(got as usize);
            println!("getgroups count={} has_root={}", got, groups.contains(&0));
        }
    }

    // umask: set twice. umask(2) returns the previous mask, so the second
    // call deterministically returns the first call's argument (0o022).
    unsafe { libc::umask(0o022) };
    let prev = unsafe { libc::umask(0o077) };
    println!("umask_prev={:o}", prev & 0o777);

    // uname(): sysname + machine should match Linux. Skip release/version.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } == 0 {
        println!("uname_sysname={}", cstr_field(&uts.sysname));
        println!("uname_machine={}", cstr_field(&uts.machine));
    } else {
        println!("uname=ERR:{}", std::io::Error::last_os_error().raw_os_error().unwrap_or(-1));
    }

    // sysinfo(): only booleans (values are non-deterministic).
    let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
    if unsafe { libc::sysinfo(&mut info) } == 0 {
        println!("sysinfo totalram_pos={} procs_ge1={}", info.totalram > 0, info.procs >= 1);
    } else {
        println!("sysinfo=ERR:{}", std::io::Error::last_os_error().raw_os_error().unwrap_or(-1));
    }

    // getpriority(PRIO_PROCESS, 0): the nice value. errno must be cleared
    // first since -1 is a legal return.
    unsafe { *libc::__errno_location() = 0 };
    let nice = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
    let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if nice == -1 && err != 0 {
        println!("getpriority=ERR:{}", err);
    } else {
        println!("getpriority_nice={}", nice);
    }

    // prctl(PR_GET_DUMPABLE).
    let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
    println!("prctl_dumpable={}", dumpable);

    // getrlimit(RLIMIT_NOFILE): booleans only.
    let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } == 0 {
        println!(
            "rlimit_nofile cur_pos={} cur_le_max={}",
            rl.rlim_cur > 0,
            rl.rlim_cur <= rl.rlim_max
        );
    } else {
        println!("rlimit_nofile=ERR:{}", std::io::Error::last_os_error().raw_os_error().unwrap_or(-1));
    }

    // sched_getaffinity / sched_yield.
    let yield_ret = unsafe { libc::sched_yield() };
    println!("sched_yield={}", yield_ret);

    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) } == 0 {
        let count = unsafe { libc::CPU_COUNT(&set) };
        println!("sched_affinity nonempty={}", count > 0);
    } else {
        println!("sched_affinity=ERR:{}", std::io::Error::last_os_error().raw_os_error().unwrap_or(-1));
    }
}

/// Decode a NUL-terminated C char array (e.g. a `utsname` field) to a String.
fn cstr_field(field: &[libc::c_char]) -> String {
    let bytes = unsafe { CStr::from_ptr(field.as_ptr()) };
    bytes.to_string_lossy().into_owned()
}
