//! POSIX message-queue probe (mq_open/mq_unlink/mq_timedsend/mq_timedreceive/
//! mq_getsetattr). Drives the raw `SYS_mq_*` syscalls (musl has no high-level
//! `mq_*` wrappers) and prints one labelled, deterministic line per observation.
//! The conformance harness runs this identical static binary under carrick and
//! real Linux and diffs line-by-line, so a divergence names the exact failing
//! behavior.
//!
//! Deterministic only: booleans, byte counts, errno names, and rendered
//! single-line content. No fd numbers, addresses, pids, or timestamps.
//!
//! NOTE: this probe is in `GATE_SKIP_PROBES` (see crates/carrick-cli/tests/
//! conformance.rs). The macOS Docker oracle (Docker Desktop / LinuxKit) cannot
//! create a POSIX message queue at all — `mq_open(O_CREAT)` returns EACCES even
//! under `--privileged`/`--ipc=host` — so carrick's correct success can never
//! MATCH it. Gate this against a native-Linux oracle (the kvm/bhyve lanes).

use std::ffi::CString;

/// `struct mq_attr` on a 64-bit kernel: eight `long` (mq_flags, mq_maxmsg,
/// mq_msgsize, mq_curmsgs, then four reserved).
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct MqAttr {
    mq_flags: i64,
    mq_maxmsg: i64,
    mq_msgsize: i64,
    mq_curmsgs: i64,
    __reserved: [i64; 4],
}

const MSGSIZE: i64 = 64;
const MAXMSG: i64 = 10;

fn main() {
    let name = "/carrick_mq_probe";
    // Start from a clean slate (ignore ENOENT).
    mq_unlink(name);

    let attr = MqAttr {
        mq_maxmsg: MAXMSG,
        mq_msgsize: MSGSIZE,
        ..Default::default()
    };

    // 1. Create the queue O_CREAT|O_RDWR with the attr.
    let mqd = mq_open(name, libc::O_CREAT | libc::O_RDWR, 0o600, Some(&attr));
    println!("mq_open_create_ok={}", mqd >= 0);
    if mqd < 0 {
        println!("mq_open_create_errno={}", errno_name(errno()));
        return;
    }

    // 2. getattr reports the geometry we created.
    let mut got = MqAttr::default();
    let r = mq_getattr(mqd, &mut got);
    println!("mq_getattr_ok={}", r == 0);
    println!("mq_getattr_maxmsg={}", got.mq_maxmsg);
    println!("mq_getattr_msgsize={}", got.mq_msgsize);
    println!("mq_getattr_curmsgs0={}", got.mq_curmsgs);

    // 3. timedsend "hello" prio 3, then timedreceive → bytes "hello" + prio 3.
    let payload = b"hello";
    let s = mq_timedsend(mqd, payload, 3, None);
    println!("mq_send_hello_ok={}", s == 0);

    let mut got = MqAttr::default();
    mq_getattr(mqd, &mut got);
    println!("mq_curmsgs_after_send={}", got.mq_curmsgs);

    let mut buf = vec![0u8; MSGSIZE as usize];
    let mut prio: u32 = 0;
    let n = mq_timedreceive(mqd, &mut buf, Some(&mut prio), None);
    println!("mq_recv_hello_len={}", n);
    println!(
        "mq_recv_hello_bytes={}",
        if n >= 0 {
            render(&buf[..n as usize])
        } else {
            format!("ERR:{}", errno_name(errno()))
        }
    );
    println!("mq_recv_hello_prio={}", prio);

    // 4. Priority ordering: send prio 1 then prio 9; receive returns prio-9 first.
    mq_timedsend(mqd, b"low", 1, None);
    mq_timedsend(mqd, b"high", 9, None);
    let (n1, p1) = recv_one(mqd);
    let (n2, p2) = recv_one(mqd);
    println!("mq_prio_first_prio={}", p1);
    println!("mq_prio_first_bytes={}", n1);
    println!("mq_prio_second_prio={}", p2);
    println!("mq_prio_second_bytes={}", n2);

    // 5. O_NONBLOCK drain → EAGAIN. Reopen the same queue O_RDONLY|O_NONBLOCK.
    let rd = mq_open(name, libc::O_RDONLY | libc::O_NONBLOCK, 0, None);
    println!("mq_open_nonblock_ok={}", rd >= 0);
    if rd >= 0 {
        // The queue is empty now; a non-blocking receive must EAGAIN.
        let mut b = vec![0u8; MSGSIZE as usize];
        let mut p: u32 = 0;
        let r = mq_timedreceive(rd, &mut b, Some(&mut p), None);
        println!(
            "mq_nonblock_empty_eagain={}",
            r < 0 && errno() == libc::EAGAIN
        );
        unsafe { libc::close(rd) };
    }

    // 6. A 50ms-in-the-past absolute timeout receive on an empty queue →
    //    ETIMEDOUT (NOT EAGAIN).
    let mut past = now_realtime();
    // 50ms in the past.
    past.tv_nsec -= 50_000_000;
    if past.tv_nsec < 0 {
        past.tv_nsec += 1_000_000_000;
        past.tv_sec -= 1;
    }
    let mut b = vec![0u8; MSGSIZE as usize];
    let mut p: u32 = 0;
    let r = mq_timedreceive(mqd, &mut b, Some(&mut p), Some(&past));
    println!(
        "mq_recv_timeout_etimedout={}",
        r < 0 && errno() == libc::ETIMEDOUT
    );

    unsafe { libc::close(mqd) };

    // 7. mq_unlink ok, then mq_open without O_CREAT → ENOENT.
    let u = mq_unlink(name);
    println!("mq_unlink_ok={}", u == 0);
    let reopened = mq_open(name, libc::O_RDWR, 0, None);
    println!(
        "mq_open_after_unlink_enoent={}",
        reopened < 0 && errno() == libc::ENOENT
    );
    if reopened >= 0 {
        unsafe { libc::close(reopened) };
    }
}

/// Receive one message, returning (byte_count, priority). On error returns
/// (-errno, 0) folded into the byte count so the line stays deterministic.
fn recv_one(mqd: i32) -> (i64, u32) {
    let mut buf = vec![0u8; MSGSIZE as usize];
    let mut prio: u32 = 0;
    let n = mq_timedreceive(mqd, &mut buf, Some(&mut prio), None);
    (n, prio)
}

// ---- Raw syscall wrappers (musl lacks the high-level mq_* functions) ----

fn mq_open(name: &str, oflag: i32, mode: u32, attr: Option<&MqAttr>) -> i32 {
    let c = CString::new(name).unwrap();
    let attr_ptr = match attr {
        Some(a) => a as *const MqAttr as usize,
        None => 0,
    };
    unsafe {
        libc::syscall(
            libc::SYS_mq_open,
            c.as_ptr(),
            oflag as libc::c_long,
            mode as libc::c_long,
            attr_ptr as libc::c_long,
        ) as i32
    }
}

fn mq_unlink(name: &str) -> i32 {
    let c = CString::new(name).unwrap();
    unsafe { libc::syscall(libc::SYS_mq_unlink, c.as_ptr()) as i32 }
}

/// mq_timedsend(mqd, msg, len, prio, abs_timeout). `None` timeout → block.
fn mq_timedsend(mqd: i32, msg: &[u8], prio: u32, timeout: Option<&libc::timespec>) -> i32 {
    let to_ptr = match timeout {
        Some(t) => t as *const libc::timespec as usize,
        None => 0,
    };
    unsafe {
        libc::syscall(
            libc::SYS_mq_timedsend,
            mqd as libc::c_long,
            msg.as_ptr() as libc::c_long,
            msg.len() as libc::c_long,
            prio as libc::c_long,
            to_ptr as libc::c_long,
        ) as i32
    }
}

/// mq_timedreceive(mqd, buf, len, &prio, abs_timeout). Returns byte count or -1.
fn mq_timedreceive(
    mqd: i32,
    buf: &mut [u8],
    prio: Option<&mut u32>,
    timeout: Option<&libc::timespec>,
) -> i64 {
    let prio_ptr = match prio {
        Some(p) => p as *mut u32 as usize,
        None => 0,
    };
    let to_ptr = match timeout {
        Some(t) => t as *const libc::timespec as usize,
        None => 0,
    };
    unsafe {
        libc::syscall(
            libc::SYS_mq_timedreceive,
            mqd as libc::c_long,
            buf.as_mut_ptr() as libc::c_long,
            buf.len() as libc::c_long,
            prio_ptr as libc::c_long,
            to_ptr as libc::c_long,
        ) as i64
    }
}

/// mq_getattr is mq_getsetattr(mqd, NULL, &out).
fn mq_getattr(mqd: i32, out: &mut MqAttr) -> i32 {
    unsafe {
        libc::syscall(
            libc::SYS_mq_getsetattr,
            mqd as libc::c_long,
            0i64,
            out as *mut MqAttr as libc::c_long,
        ) as i32
    }
}

fn now_realtime() -> libc::timespec {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    ts
}

/// Render bytes as an ASCII string if printable, else hex — single line.
fn render(bytes: &[u8]) -> String {
    if bytes.iter().all(|&b| (0x20..0x7f).contains(&b)) {
        String::from_utf8_lossy(bytes).into_owned()
    } else {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

/// Stable errno name for the handful of values this probe checks.
fn errno_name(e: i32) -> String {
    match e {
        libc::ENOENT => "ENOENT".to_string(),
        libc::EAGAIN => "EAGAIN".to_string(),
        libc::ETIMEDOUT => "ETIMEDOUT".to_string(),
        libc::EEXIST => "EEXIST".to_string(),
        libc::EMSGSIZE => "EMSGSIZE".to_string(),
        libc::EBADF => "EBADF".to_string(),
        libc::EINVAL => "EINVAL".to_string(),
        other => format!("E{}", other),
    }
}
