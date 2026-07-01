//! MAP_SHARED|MAP_ANON coherence across NESTED fork + signal delivery — the
//! LTP tst_test results-page structure that sigtimedwait01 exercises on the
//! x86 lanes: the lib process maps a shared results page, forks the test
//! process, which forks a signal-sender child, takes an EINTR, then increments
//! the shared page. Under carrick/bhyve the increment vanished (`TBROK: Test 0
//! haven't reported results!`) — this probe isolates WHICH hop loses it:
//!   inc_before_fork  — test-proc increment BEFORE its nested fork
//!   own_after_fork   — test proc reads back its own post-fork increment
//!   parent_sees_*    — the outer (lib-analog) process's view of each
//!   child_inc_seen   — a grandchild increment seen by the outer process

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

static USR1_HITS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_usr1(_sig: i32) {
    USR1_HITS.fetch_add(1, Ordering::SeqCst);
}

unsafe fn rt_sigtimedwait_empty(timeout: Duration) -> (i64, i32) {
    let set = 0u64;
    let ts = libc::timespec {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_nsec: timeout.subsec_nanos() as libc::c_long,
    };
    let rc = libc::syscall(
        libc::SYS_rt_sigtimedwait,
        &set as *const u64,
        core::ptr::null_mut::<libc::c_void>(),
        &ts as *const libc::timespec,
        8usize,
    ) as i64;
    (
        rc,
        if rc < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        } else {
            0
        },
    )
}

fn main() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_usr1 as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());

        let page = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANON,
            -1,
            0,
        );
        if page == libc::MAP_FAILED {
            println!("mmap_ok=false");
            return;
        }
        let slots = page as *mut u64; // [0]=pre-fork inc, [1]=post-fork inc, [2]=grandchild inc

        let test_proc = libc::fork();
        if test_proc == 0 {
            // "test process": increment BEFORE the nested fork.
            *slots.add(0) += 1;

            let me = libc::getpid();
            let sig_child = libc::fork();
            if sig_child == 0 {
                // "signal sender": one SIGUSR1 to the test proc + a shared
                // increment of its own, then exit.
                libc::usleep(150_000);
                libc::kill(me, libc::SIGUSR1);
                *slots.add(2) += 1;
                libc::_exit(0);
            }

            // Wait for the EINTR (bounded), then increment AFTER the fork —
            // the write that vanished under carrick/bhyve.
            let (rc, err) = rt_sigtimedwait_empty(Duration::from_secs(6));
            let eintr = rc == -1 && err == libc::EINTR;
            *slots.add(1) += 1;
            // Read back through the same mapping — detects a write that went
            // to a detached copy (would still read 1) vs one that was undone.
            let own = core::ptr::read_volatile(slots.add(1));
            let mut status = 0;
            libc::waitpid(sig_child, &mut status, 0);
            // Report via exit code: bit0 = EINTR seen, bit1 = own read-back ok.
            libc::_exit((eintr as i32) | ((own == 1) as i32) << 1);
        }

        let mut status = 0;
        libc::waitpid(test_proc, &mut status, 0);
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        println!("test_proc_eintr={}", code >= 0 && code & 1 != 0);
        println!("own_after_fork={}", code >= 0 && code & 2 != 0);
        println!(
            "parent_sees_prefork={}",
            core::ptr::read_volatile(slots.add(0)) == 1
        );
        println!(
            "parent_sees_postfork={}",
            core::ptr::read_volatile(slots.add(1)) == 1
        );
        println!(
            "child_inc_seen={}",
            core::ptr::read_volatile(slots.add(2)) == 1
        );
    }
}
