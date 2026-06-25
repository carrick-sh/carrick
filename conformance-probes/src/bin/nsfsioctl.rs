//! nsfs `NS_GET_*` ioctl probe (ioctl_ns(2)). Opens each /proc/self/ns/<type>
//! magic link and exercises the namespace-introspection ioctls on the resulting
//! fd. This is the reducer for LTP ioctl_ns02/ioctl_ns03/ioctl_ns04: carrick
//! models exactly ONE initial namespace per type, so the answers are synthetic
//! but must be STABLE and consistent with Linux.
//!
//! The conformance harness runs this identical static binary under carrick and
//! real Linux and diffs line by line. Deterministic only: booleans, named
//! CLONE_NEW* flag constants, errno values, and a uid — NEVER a raw inode
//! literal or a pid (those differ run-to-run and host-to-host).
//!
//! NS_GET_* use the 0xb7 type byte in the _IO(type, nr) form — no size/dir bits
//! — so the request is just (0xb7 << 8) | nr. Encoded as raw literals here.

use std::ffi::CString;

// `libc::ioctl`'s request argument is `libc::Ioctl`, whose width differs by
// target (i32 on musl-linux). The NSIO request numbers fit either width.
const NS_GET_USERNS: libc::Ioctl = 0xb701;
const NS_GET_PARENT: libc::Ioctl = 0xb702;
const NS_GET_NSTYPE: libc::Ioctl = 0xb703;
const NS_GET_OWNER_UID: libc::Ioctl = 0xb704;

// CLONE_NEW* flag values (clone(2)). NS_GET_NSTYPE returns one of these; print
// the symbolic name keyed off the value so the line is host-stable.
const CLONE_NEWNS: i64 = 0x0002_0000;
const CLONE_NEWCGROUP: i64 = 0x0200_0000;
const CLONE_NEWUTS: i64 = 0x0400_0000;
const CLONE_NEWIPC: i64 = 0x0800_0000;
const CLONE_NEWUSER: i64 = 0x1000_0000;
const CLONE_NEWPID: i64 = 0x2000_0000;
const CLONE_NEWNET: i64 = 0x4000_0000;
const CLONE_NEWTIME: i64 = 0x0000_0080;

/// The ns types ioctl_ns exercises, in a stable order.
const NS_TYPES: &[&str] = &["mnt", "uts", "ipc", "net", "pid", "user", "cgroup", "time"];

fn main() {
    // (a) Each /proc/self/ns/<type> must be openable.
    for ns in NS_TYPES {
        let fd = open_ns(ns);
        println!("{ns}_open_ok={}", fd >= 0);
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }

    // (b) NS_GET_NSTYPE returns the CLONE_NEW* flag for the link's type.
    for ns in NS_TYPES {
        let fd = open_ns(ns);
        if fd < 0 {
            println!("{ns}_nstype=ERR:{}", errno());
            continue;
        }
        let r = unsafe { libc::ioctl(fd, NS_GET_NSTYPE) };
        println!("{ns}_nstype={}", clone_flag_name(r as i64));
        unsafe { libc::close(fd) };
    }

    // (c) NS_GET_OWNER_UID on the user-ns fd — the initial user ns owner (root).
    {
        let fd = open_ns("user");
        if fd < 0 {
            println!("user_owner_uid=ERR:{}", errno());
        } else {
            let mut uid: libc::uid_t = 0xffff_ffff;
            let r = unsafe { libc::ioctl(fd, NS_GET_OWNER_UID, &mut uid as *mut libc::uid_t) };
            if r < 0 {
                println!("user_owner_uid=ERR:{}", errno());
            } else {
                println!("user_owner_uid={uid}");
            }
            unsafe { libc::close(fd) };
        }
    }

    // (d) NS_GET_PARENT on the user-ns fd — no accessible parent → EPERM.
    {
        let fd = open_ns("user");
        if fd < 0 {
            println!("user_parent=ERR:{}", errno());
        } else {
            let r = unsafe { libc::ioctl(fd, NS_GET_PARENT) };
            if r < 0 {
                println!("user_parent_errno={}", errno());
            } else {
                // Unexpected success — still close the returned fd.
                println!("user_parent_errno=0");
                unsafe { libc::close(r) };
            }
            unsafe { libc::close(fd) };
        }
    }

    // (e) Two opens of /proc/self/ns/user fstat to the same st_ino (same-ns
    //     equality). Print only the boolean, never the inode itself.
    {
        let a = open_ns("user");
        let b = open_ns("user");
        if a < 0 || b < 0 {
            println!("user_ino_equal=ERR:{}", errno());
        } else {
            let ina = stat_ino(a);
            let inb = stat_ino(b);
            println!("user_ino_equal={}", ina.is_some() && ina == inb);
        }
        if a >= 0 {
            unsafe { libc::close(a) };
        }
        if b >= 0 {
            unsafe { libc::close(b) };
        }
    }

    // NS_GET_USERNS returns a fresh fd on the owning (initial) user namespace.
    {
        let fd = open_ns("uts");
        if fd < 0 {
            println!("userns_from_uts_ok=ERR:{}", errno());
        } else {
            let r = unsafe { libc::ioctl(fd, NS_GET_USERNS) };
            println!("userns_from_uts_ok={}", r >= 0);
            if r >= 0 {
                unsafe { libc::close(r) };
            }
            unsafe { libc::close(fd) };
        }
    }
}

/// Open /proc/self/ns/<ns> O_RDONLY, returning the raw fd (or -1).
fn open_ns(ns: &str) -> i32 {
    open(&format!("/proc/self/ns/{ns}"), libc::O_RDONLY)
}

/// The symbolic CLONE_NEW* name for a NS_GET_NSTYPE return value, so the printed
/// line is identical across hosts. `ERR:<errno>` for a failed ioctl; `?:<v>` for
/// an unrecognised value.
fn clone_flag_name(v: i64) -> String {
    if v < 0 {
        return format!("ERR:{}", errno());
    }
    match v {
        CLONE_NEWNS => "CLONE_NEWNS".to_string(),
        CLONE_NEWCGROUP => "CLONE_NEWCGROUP".to_string(),
        CLONE_NEWUTS => "CLONE_NEWUTS".to_string(),
        CLONE_NEWIPC => "CLONE_NEWIPC".to_string(),
        CLONE_NEWUSER => "CLONE_NEWUSER".to_string(),
        CLONE_NEWPID => "CLONE_NEWPID".to_string(),
        CLONE_NEWNET => "CLONE_NEWNET".to_string(),
        CLONE_NEWTIME => "CLONE_NEWTIME".to_string(),
        other => format!("?:{other}"),
    }
}

/// fstat the fd and return its st_ino (or None on error).
fn stat_ino(fd: i32) -> Option<u64> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st as *mut libc::stat) } < 0 {
        None
    } else {
        Some(st.st_ino as u64)
    }
}

/// Open helper returning the raw fd (or -1 on error).
fn open(path: &str, flags: i32) -> i32 {
    let c = match CString::new(path) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    unsafe { libc::open(c.as_ptr(), flags) }
}

/// Current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}
