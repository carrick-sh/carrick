// Probe D — FP/SIMD preservation across signals. Workers repeatedly fill a
// buffer and memcpy it (aarch64 memcpy uses SIMD q-registers), verifying the
// copy byte-for-byte. A SIGURG handler deliberately CLOBBERS V0–V7,V16–V23 with
// garbage, and a sysmon storms SIGURG. If the kernel (carrick) preserves the
// interrupted thread's FP/SIMD state across the handler, every copy verifies;
// if not, a memcpy interrupted mid-flight resumes with clobbered vector
// registers and produces a wrong copy -> "FP_CORRUPTION".
//
// Expected: PROBE_D_OK with carrick FP save/restore on; FP_CORRUPTION with
// CARRICK_NO_FPSIMD=1. This is the direct correctness test for the fpsimd_context
// save/restore.
use std::env;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

static PREEMPTS: AtomicU64 = AtomicU64::new(0);

#[cfg(target_arch = "aarch64")]
extern "C" fn on_sigurg(_sig: i32, _info: *mut libc::siginfo_t, _uc: *mut libc::c_void) {
    // Trash a representative set of vector registers with a recognisable
    // pattern. If carrick doesn't restore the interrupted FP state, an
    // interrupted memcpy resumes using these bytes.
    unsafe {
        core::arch::asm!(
            "movi v0.16b, #0xA5",
            "movi v1.16b, #0xA5",
            "movi v2.16b, #0xA5",
            "movi v3.16b, #0xA5",
            "movi v4.16b, #0xA5",
            "movi v5.16b, #0xA5",
            "movi v6.16b, #0xA5",
            "movi v7.16b, #0xA5",
            "movi v16.16b, #0xA5",
            "movi v17.16b, #0xA5",
            "movi v18.16b, #0xA5",
            "movi v19.16b, #0xA5",
            "movi v20.16b, #0xA5",
            "movi v21.16b, #0xA5",
            "movi v22.16b, #0xA5",
            "movi v23.16b, #0xA5",
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v21") _, out("v22") _, out("v23") _,
            options(nostack, nomem),
        );
    }
    PREEMPTS.fetch_add(1, Ordering::Relaxed);
}

fn install_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_sigurg as usize;
        sa.sa_flags = libc::SA_RESTART | libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        assert_eq!(
            libc::sigaction(libc::SIGURG, &sa, std::ptr::null_mut()),
            0,
            "sigaction(SIGURG) failed"
        );
    }
}

fn gettid() -> i32 {
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

fn main() {
    let mut args = env::args().skip(1);
    let workers: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(4);
    let iters: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(200_000);

    install_handler();
    let start = Instant::now();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(500));
        if start.elapsed() >= Duration::from_secs(40) {
            eprintln!("PROBE_D_TIMEOUT preempts={}", PREEMPTS.load(Ordering::Relaxed));
            std::process::exit(2);
        }
    });

    let pid = unsafe { libc::getpid() };
    let tids: Arc<Mutex<Vec<i32>>> = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let corrupt = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::new();
    for _ in 0..workers {
        let tids = Arc::clone(&tids);
        let done = Arc::clone(&done);
        let corrupt = Arc::clone(&corrupt);
        handles.push(thread::spawn(move || {
            tids.lock().unwrap().push(gettid());
            // 64 KiB buffers force the SIMD bulk-copy path and widen the
            // interrupt window.
            let n = 64 * 1024;
            let mut src = vec![0u8; n];
            let mut dst = vec![0u8; n];
            for it in 0..iters {
                let b = (it & 0xff) as u8;
                for (i, s) in src.iter_mut().enumerate() {
                    *s = b ^ (i as u8);
                }
                dst.copy_from_slice(&src); // SIMD memcpy
                if dst != src {
                    corrupt.store(true, Ordering::Relaxed);
                    done.store(true, Ordering::Relaxed);
                    return;
                }
            }
        }));
    }

    let sysmon = {
        let tids = Arc::clone(&tids);
        let done = Arc::clone(&done);
        thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                for tid in tids.lock().unwrap().clone() {
                    unsafe {
                        libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGURG);
                    }
                }
                thread::sleep(Duration::from_micros(30));
            }
        })
    };

    for h in handles {
        h.join().unwrap();
    }
    done.store(true, Ordering::Relaxed);
    sysmon.join().unwrap();

    if corrupt.load(Ordering::Relaxed) {
        println!("FP_CORRUPTION preempts={}", PREEMPTS.load(Ordering::Relaxed));
        std::process::exit(1);
    }
    println!("PROBE_D_OK {iters} preempts={}", PREEMPTS.load(Ordering::Relaxed));
}
