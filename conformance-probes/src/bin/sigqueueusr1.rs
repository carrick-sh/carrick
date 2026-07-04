//! Cross-process standard-signal sigqueue payload. A parent queues SIGUSR1 with
//! a sigval to a forked child; the child's SA_SIGINFO handler must observe
//! SI_QUEUE and the payload, not a host-kill-shaped zero siginfo.

use conformance_probes::report;
use std::sync::atomic::{AtomicI32, Ordering};

const PAYLOAD: i32 = 777;
static CODE: AtomicI32 = AtomicI32::new(0);
static VALUE: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_usr1(_sig: libc::c_int, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    if info.is_null() {
        return;
    }
    let p = info as *const u8;
    unsafe {
        CODE.store(
            core::ptr::read_unaligned(p.add(8) as *const i32),
            Ordering::SeqCst,
        );
        VALUE.store(
            core::ptr::read_unaligned(p.add(24) as *const i32),
            Ordering::SeqCst,
        );
    }
}

fn main() {
    unsafe {
        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = on_usr1 as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        let install_ok = libc::sigaction(libc::SIGUSR1, &sa, core::ptr::null_mut()) == 0;

        let mut ready = [0; 2];
        let pipe_ok = libc::pipe(ready.as_mut_ptr()) == 0;
        if !install_ok || !pipe_ok {
            report!(setup_ok = false);
            return;
        }

        let pid = libc::fork();
        if pid == 0 {
            libc::close(ready[0]);
            let _ = libc::write(ready[1], b"r".as_ptr() as *const libc::c_void, 1);
            for _ in 0..3000 {
                if CODE.load(Ordering::SeqCst) != 0 {
                    break;
                }
                libc::usleep(1000);
            }
            report!(
                sigqueue_usr1_delivered = CODE.load(Ordering::SeqCst) != 0,
                sigqueue_usr1_code_is_queue = CODE.load(Ordering::SeqCst) == libc::SI_QUEUE,
                sigqueue_usr1_payload = VALUE.load(Ordering::SeqCst) == PAYLOAD,
            );
            libc::_exit(0);
        }

        libc::close(ready[1]);
        let mut b = [0u8; 1];
        let _ = libc::read(ready[0], b.as_mut_ptr() as *mut libc::c_void, 1);
        let val = libc::sigval {
            sival_ptr: PAYLOAD as usize as *mut libc::c_void,
        };
        let queue_ok = libc::sigqueue(pid, libc::SIGUSR1, val) == 0;
        let mut st = 0;
        let _ = libc::waitpid(pid, &mut st, 0);
        report!(sigqueue_usr1_queue_ok = queue_ok);
    }
}
