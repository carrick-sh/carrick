//! Cross-process RT-signal (sigqueue) probe: parent sigqueue()s SIGRTMIN+payload
//! to a forked child; the child's SA_SIGINFO handler must see si_code==SI_QUEUE
//! (-1) and the si_value payload. macOS has no signals 32-64, so carrick must
//! deliver this via its internal explicit-signal ring (not a host kill).
//! Deterministic: prints rt_code, rt_value, correct=0/1.
use std::sync::atomic::{AtomicI32, AtomicI64, Ordering};
static CODE: AtomicI32 = AtomicI32::new(0);
static VAL: AtomicI64 = AtomicI64::new(-1);
const PAYLOAD: i64 = 0xCAFE;
extern "C" fn on_rt(_sig: libc::c_int, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    if info.is_null() { return; }
    // si_code @ offset 8, si_value (sigval) @ offset 24 in the Linux siginfo_t.
    let p = info as *const u8;
    CODE.store(unsafe { std::ptr::read_unaligned(p.add(8) as *const i32) }, Ordering::SeqCst);
    VAL.store(unsafe { std::ptr::read_unaligned(p.add(24) as *const i64) }, Ordering::SeqCst);
}
fn main() { unsafe {
    let rt = libc::SIGRTMIN();
    let mut sa: libc::sigaction = std::mem::zeroed();
    sa.sa_sigaction = on_rt as usize;
    libc::sigemptyset(&mut sa.sa_mask);
    sa.sa_flags = libc::SA_SIGINFO;
    libc::sigaction(rt, &sa, std::ptr::null_mut());
    let mut ready = [0i32; 2];
    libc::pipe(ready.as_mut_ptr());
    let pid = libc::fork();
    if pid == 0 {
        libc::write(ready[1], b"r".as_ptr() as *const libc::c_void, 1);
        let mut i = 0;
        while VAL.load(Ordering::SeqCst) == -1 && i < 3000 { libc::usleep(1000); i += 1; }
        let v = VAL.load(Ordering::SeqCst);
        let c = CODE.load(Ordering::SeqCst);
        println!("rt_code={} rt_value=0x{:x} correct={}", c, v, ((v == PAYLOAD) && (c == -1)) as i32);
        libc::_exit(0);
    }
    let mut b = [0u8; 1];
    libc::read(ready[0], b.as_mut_ptr() as *mut libc::c_void, 1);
    libc::usleep(200_000);
    let val = libc::sigval { sival_ptr: PAYLOAD as usize as *mut libc::c_void };
    libc::sigqueue(pid, rt, val);
    let mut st = 0; libc::waitpid(pid, &mut st, 0);
} }
