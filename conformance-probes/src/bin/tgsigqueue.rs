//! rt_tgsigqueueinfo(2): queue a signal with a caller-supplied siginfo to a
//! specific (tgid, tid), delivering the si_value payload to the SA_SIGINFO
//! handler. Stands in for LTP rt_tgsigqueueinfo01 (signal-to-self leg).
//! carrick had no syscall 240 (TCONF on the LTP test); this exercises the
//! same delivery machinery as rt_sigqueueinfo but via the tgid+tid form.

use conformance_probes::{block_signal, errno, unblock_signal};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

const PAYLOAD: i32 = 0x00B0_0B15;
static HITS: AtomicU32 = AtomicU32::new(0);
static OBSERVED_VALUE: AtomicI32 = AtomicI32::new(0);
static OBSERVED_SIGNO: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_rt(_sig: i32, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    HITS.fetch_add(1, Ordering::SeqCst);
    if !info.is_null() {
        unsafe {
            OBSERVED_SIGNO.store((*info).si_signo, Ordering::SeqCst);
            let base = info as *const u8;
            // si_value.sival_int sits at byte 0x18 in the aarch64 uapi layout.
            OBSERVED_VALUE.store(core::ptr::read(base.add(0x18) as *const i32), Ordering::SeqCst);
        }
    }
}

fn main() {
    unsafe {
        let sig = libc::SIGRTMIN();
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_rt as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        if libc::sigaction(sig, &sa, std::ptr::null_mut()) != 0 {
            println!("install_ok=false");
            return;
        }

        let _ = block_signal(sig);

        let mut info: libc::siginfo_t = std::mem::zeroed();
        let info_bytes = &mut info as *mut libc::siginfo_t as *mut u8;
        core::ptr::write(info_bytes.add(0) as *mut i32, sig); // si_signo
        core::ptr::write(info_bytes.add(8) as *mut i32, libc::SI_QUEUE); // si_code
        core::ptr::write(info_bytes.add(0x18) as *mut i32, PAYLOAD); // sival_int

        let tgid = libc::getpid() as i64;
        let tid = libc::syscall(libc::SYS_gettid) as i64;
        let rc = libc::syscall(
            libc::SYS_rt_tgsigqueueinfo,
            tgid,
            tid,
            sig as i64,
            &info as *const _,
        ) as i32;
        let queue_errno = if rc < 0 { errno() } else { 0 };

        let _ = unblock_signal(sig);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while HITS.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
            std::hint::spin_loop();
        }

        println!("rt_tgsigqueueinfo_rc_ok={}", rc == 0);
        println!("rt_tgsigqueueinfo_errno={}", queue_errno);
        println!("handler_delivered={}", HITS.load(Ordering::SeqCst) >= 1);
        println!(
            "handler_signo_matches={}",
            OBSERVED_SIGNO.load(Ordering::SeqCst) == sig
        );
        println!(
            "handler_sival_int_propagated={}",
            OBSERVED_VALUE.load(Ordering::SeqCst) == PAYLOAD
        );
    }
}
