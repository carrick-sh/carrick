//! Process / system-info probe. Exercises uname/sysinfo/getrlimit/prlimit64/
//! prctl/getrandom/sched_getaffinity/sched_yield/getpriority/gettid/umask/
//! getcpu/capget and prints one labelled line per observation. The conformance
//! harness runs this identical static binary under carrick and real Linux and
//! diffs line by line — a divergent line names the exact failing syscall.
//!
//! Deterministic only: machine-varying values (uptime, free/total memory,
//! random bytes, pids, addresses, hostnames, cpu indices, limit amounts) are
//! NEVER printed. Each observation is reduced to a boolean, a fixed constant,
//! an errno, or a relationship. Output is byte-identical across runs on the
//! same machine; getrandom's "differ" bool is randomness-derived but
//! deterministic-by-design (two distinct 16-byte draws differ with
//! overwhelming probability).

use std::ffi::CStr;

fn main() {
    // uname(2): sysname should be "Linux" and machine "aarch64". Release,
    // version and nodename vary between machines/kernels so are not printed.
    {
        let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
        if unsafe { libc::uname(&mut uts) } == 0 {
            println!("uname_sysname_linux={}", cstr_field(&uts.sysname) == "Linux");
            println!("uname_machine_aarch64={}", cstr_field(&uts.machine) == "aarch64");
        } else {
            println!("uname=ERR:{}", errno());
        }
    }

    // sysinfo(2): only booleans (the amounts are non-deterministic).
    {
        let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::sysinfo(&mut info) };
        if rc == 0 {
            println!("sysinfo_ok={}", rc == 0);
            println!("sysinfo_mem_unit_pos={}", info.mem_unit > 0);
            println!("sysinfo_totalram_pos={}", info.totalram > 0);
        } else {
            println!("sysinfo=ERR:{}", errno());
        }
    }

    // getrlimit(2) RLIMIT_NOFILE / RLIMIT_STACK: rc and cur<=max only. The
    // actual limit amounts differ between machines/configs so are not printed.
    {
        let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) };
        if rc == 0 {
            println!("getrlimit_nofile_ok={}", rc == 0);
            println!("getrlimit_nofile_cur_le_max={}", rl.rlim_cur <= rl.rlim_max);
        } else {
            println!("getrlimit_nofile=ERR:{}", errno());
        }
    }
    {
        let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_STACK, &mut rl) };
        if rc == 0 {
            println!("getrlimit_stack_ok={}", rc == 0);
            println!("getrlimit_stack_cur_le_max={}", rl.rlim_cur <= rl.rlim_max);
        } else {
            println!("getrlimit_stack=ERR:{}", errno());
        }
    }

    // prlimit64(2) RLIMIT_NOFILE / RLIMIT_STACK (no get-only libc wrapper, so
    // use the raw syscall with a NULL new_limit to query).
    {
        let mut rl: libc::rlimit64 = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::syscall(
                libc::SYS_prlimit64,
                0,
                libc::RLIMIT_NOFILE,
                std::ptr::null::<libc::rlimit64>(),
                &mut rl as *mut libc::rlimit64,
            )
        };
        if rc == 0 {
            println!("prlimit64_nofile_ok={}", rc == 0);
            println!("prlimit64_nofile_cur_le_max={}", rl.rlim_cur <= rl.rlim_max);
        } else {
            println!("prlimit64_nofile=ERR:{}", errno());
        }
    }
    {
        let mut rl: libc::rlimit64 = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::syscall(
                libc::SYS_prlimit64,
                0,
                libc::RLIMIT_STACK,
                std::ptr::null::<libc::rlimit64>(),
                &mut rl as *mut libc::rlimit64,
            )
        };
        if rc == 0 {
            println!("prlimit64_stack_ok={}", rc == 0);
            println!("prlimit64_stack_cur_le_max={}", rl.rlim_cur <= rl.rlim_max);
        } else {
            println!("prlimit64_stack=ERR:{}", errno());
        }
    }

    // prctl(PR_SET_NAME) then PR_GET_NAME: confirm the name round-trips. The
    // kernel buffer is 16 bytes including NUL; "probename" fits.
    {
        let set_name = b"probename\0";
        let set_rc =
            unsafe { libc::prctl(libc::PR_SET_NAME, set_name.as_ptr() as libc::c_ulong, 0, 0, 0) };
        if set_rc != 0 {
            println!("prctl_name=ERR:{}", errno());
        } else {
            let mut buf = [0u8; 16];
            let get_rc =
                unsafe { libc::prctl(libc::PR_GET_NAME, buf.as_mut_ptr() as libc::c_ulong, 0, 0, 0) };
            if get_rc != 0 {
                println!("prctl_name=ERR:{}", errno());
            } else {
                let readback = CStr::from_bytes_until_nul(&buf)
                    .ok()
                    .map(|c| c.to_string_lossy().into_owned())
                    .unwrap_or_default();
                println!("prctl_name_roundtrip={}", readback == "probename");
            }
        }
    }

    // getrandom(2): request 16 bytes twice. Both calls should return 16; the
    // two buffers should DIFFER (random — guards against constant/zero output).
    // The bytes themselves are never printed.
    {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        let n1 = unsafe {
            libc::syscall(libc::SYS_getrandom, a.as_mut_ptr() as *mut libc::c_void, a.len(), 0)
        };
        let n2 = unsafe {
            libc::syscall(libc::SYS_getrandom, b.as_mut_ptr() as *mut libc::c_void, b.len(), 0)
        };
        if n1 < 0 || n2 < 0 {
            println!("getrandom=ERR:{}", errno());
        } else {
            println!("getrandom_both_16={}", n1 == 16 && n2 == 16);
            println!("getrandom_differ={}", a != b);
        }
    }

    // sched_getaffinity(2): success + at least one CPU set. The cpu count
    // varies between machines so is not printed.
    {
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set)
        };
        if rc == 0 {
            println!("sched_getaffinity_ok={}", rc == 0);
            println!("sched_getaffinity_has_cpu={}", unsafe { libc::CPU_COUNT(&set) } > 0);
        } else {
            println!("sched_getaffinity=ERR:{}", errno());
        }
    }

    // sched_yield(2): returns 0 on success.
    {
        let rc = unsafe { libc::sched_yield() };
        println!("sched_yield_ok={}", rc == 0);
    }

    // getpriority(PRIO_PROCESS, 0): a fresh process has nice 0 on both. errno
    // must be cleared first since -1 is a legal return value.
    {
        unsafe { *libc::__errno_location() = 0 };
        let nice = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
        let err = errno();
        if nice == -1 && err != 0 {
            println!("getpriority=ERR:{}", err);
        } else {
            println!("getpriority_nice={}", nice);
        }
    }

    // gettid() vs getpid(): equal in a single-threaded process. Never print
    // the actual ids.
    {
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as libc::pid_t;
        let pid = unsafe { libc::getpid() };
        println!("gettid_eq_getpid={}", tid == pid);
    }

    // umask(2): set 0o022 (returns previous), then restore (returns 0o022).
    // The second call's return value is deterministic on both platforms.
    {
        let prev = unsafe { libc::umask(0o022) };
        let second = unsafe { libc::umask(prev) };
        println!("umask_set_return={:o}", second & 0o777);
    }

    // getcpu(2): success only. The cpu/node indices vary, so are not printed.
    {
        let mut cpu: libc::c_uint = 0;
        let mut node: libc::c_uint = 0;
        let rc = unsafe {
            libc::syscall(
                libc::SYS_getcpu,
                &mut cpu as *mut libc::c_uint,
                &mut node as *mut libc::c_uint,
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        if rc == 0 {
            println!("getcpu_ok={}", rc == 0);
        } else {
            println!("getcpu=ERR:{}", errno());
        }
    }

    // capget(2): query our own capabilities. Many carrick stubs return 0 or
    // ENOSYS — printing rc-or-errno makes the diff reveal the gap. The actual
    // capability bitsets are not printed (they could differ).
    {
        #[repr(C)]
        struct CapHeader {
            version: u32,
            pid: libc::c_int,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct CapData {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        // _LINUX_CAPABILITY_VERSION_3
        let mut hdr = CapHeader { version: 0x20080522, pid: 0 };
        let mut data = [CapData { effective: 0, permitted: 0, inheritable: 0 }; 2];
        let rc = unsafe {
            libc::syscall(
                libc::SYS_capget,
                &mut hdr as *mut CapHeader,
                data.as_mut_ptr(),
            )
        };
        if rc == 0 {
            println!("capget_ok={}", rc == 0);
        } else {
            println!("capget=ERR:{}", errno());
        }
    }
}

/// Decode a NUL-terminated C char array (e.g. a `utsname` field) to a String.
fn cstr_field(field: &[libc::c_char]) -> String {
    let s = unsafe { CStr::from_ptr(field.as_ptr()) };
    s.to_string_lossy().into_owned()
}

/// Current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}
