//! Two live threads with mapped, never-touched alternate signal stacks
//! taking SA_ONSTACK|SA_SIGINFO|SA_RESTART SIGURG deliveries (#3004).
#![allow(clippy::unwrap_used)]

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

const THREADS: usize = 2;
const ROUNDS: usize = 200;
const ALT: usize = 64 * 1024;
const READY_MSG: &[u8; 5] = b"READY";
const GO_MSG: &[u8; 7] = b"UNBLOCK";
const PIPE_MSG: &[u8; 7] = b"CARRICK";

static STOP: AtomicBool = AtomicBool::new(false);
static BAD: AtomicUsize = AtomicUsize::new(0);
static WORKER_PTHREAD: [AtomicUsize; THREADS] = [const { AtomicUsize::new(0) }; THREADS];
static ALT_LO: [AtomicUsize; THREADS] = [const { AtomicUsize::new(0) }; THREADS];
static HITS: [AtomicUsize; THREADS] = [const { AtomicUsize::new(0) }; THREADS];
static READY_WR: [AtomicI32; THREADS] = [const { AtomicI32::new(-1) }; THREADS];
static GO_RD: [AtomicI32; THREADS] = [const { AtomicI32::new(-1) }; THREADS];
static ACK_WR: [AtomicI32; THREADS] = [const { AtomicI32::new(-1) }; THREADS];

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

extern "C" fn handler(sig: libc::c_int, info: *mut libc::siginfo_t, uc: *mut libc::c_void) {
    if sig != libc::SIGURG || info.is_null() || uc.is_null() {
        BAD.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let self_id = unsafe { libc::pthread_self() } as usize;
    let mut index = None;
    for (i, slot) in WORKER_PTHREAD.iter().enumerate() {
        if slot.load(Ordering::Acquire) == self_id {
            index = Some(i);
            break;
        }
    }
    let Some(i) = index else {
        BAD.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let probe = 0u8;
    let sp = (&raw const probe) as usize;
    let lo = ALT_LO[i].load(Ordering::Acquire);
    if lo == 0 || sp < lo || sp >= lo + ALT {
        BAD.fetch_add(1, Ordering::Relaxed);
    }
    HITS[i].fetch_add(1, Ordering::Release);
    let fd = ACK_WR[i].load(Ordering::Acquire);
    let byte = [1u8];
    if unsafe { libc::write(fd, byte.as_ptr().cast(), 1) } != 1 {
        BAD.fetch_add(1, Ordering::Relaxed);
    }
}

fn wait_bytes<const N: usize>(fd: i32, timeout_ms: i32) -> Result<[u8; N], i32> {
    let mut buf = [0u8; N];
    let mut off = 0;
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    while off < N {
        let prc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if prc < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return Err(96);
        }
        if prc == 0 {
            return Err(96);
        }
        let rrc = unsafe { libc::read(fd, buf[off..].as_mut_ptr().cast(), N - off) };
        if rrc < 0 && errno() == libc::EINTR {
            continue;
        }
        if rrc <= 0 {
            return Err(96);
        }
        off += rrc as usize;
    }
    Ok(buf)
}

extern "C" fn worker(arg: *mut libc::c_void) -> *mut libc::c_void {
    let i = arg as usize;
    let expected_gid = unsafe { libc::getgid() };
    WORKER_PTHREAD[i].store(unsafe { libc::pthread_self() } as usize, Ordering::Release);

    let mut spipe = [-1i32; 2];
    if unsafe { libc::pipe(spipe.as_mut_ptr()) } != 0 {
        BAD.fetch_add(1, Ordering::Relaxed);
    }

    let mut urg_set: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut base_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut urg_set);
        libc::sigaddset(&mut urg_set, libc::SIGURG);
        if libc::pthread_sigmask(libc::SIG_BLOCK, &urg_set, &mut base_mask) != 0
            || libc::sigismember(&base_mask, libc::SIGURG) != 0
        {
            BAD.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Map the alternate signal stack anonymously and never touch it before
    // the first SIGURG writes a frame onto its top page.
    let alt = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            ALT,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if alt == libc::MAP_FAILED {
        BAD.fetch_add(1, Ordering::Relaxed);
        let fd = READY_WR[i].load(Ordering::Acquire);
        let err_msg = *b"ERROR";
        unsafe { libc::write(fd, err_msg.as_ptr().cast(), err_msg.len()) };
        return std::ptr::null_mut();
    }
    ALT_LO[i].store(alt as usize, Ordering::Release);
    let ss = libc::stack_t {
        ss_sp: alt,
        ss_flags: 0,
        ss_size: ALT,
    };
    if unsafe { libc::sigaltstack(&ss, std::ptr::null_mut()) } != 0 {
        BAD.fetch_add(1, Ordering::Relaxed);
    }
    let ready_fd = READY_WR[i].load(Ordering::Acquire);
    if unsafe { libc::write(ready_fd, READY_MSG.as_ptr().cast(), READY_MSG.len()) }
        != READY_MSG.len() as isize
    {
        BAD.fetch_add(1, Ordering::Relaxed);
    }

    match wait_bytes::<7>(GO_RD[i].load(Ordering::Acquire), 5000) {
        Ok(got) if &got == GO_MSG => {}
        _ => {
            BAD.fetch_add(1, Ordering::Relaxed);
            return std::ptr::null_mut();
        }
    }
    if HITS[i].load(Ordering::Acquire) != 0 {
        BAD.fetch_add(1, Ordering::Relaxed);
    }

    // Round 0: SIGURG was queued while masked, so sigsuspend(&base_mask) is
    // deterministically the checkpoint that takes the untouched-altstack
    // delivery and must return -1/EINTR with SIGURG still blocked after sigreturn.
    let ssrc = unsafe { libc::sigsuspend(&base_mask) };
    if ssrc != -1 || errno() != libc::EINTR {
        BAD.fetch_add(1, Ordering::Relaxed);
    }
    let after_r0 = HITS[i].load(Ordering::Acquire);
    if after_r0 == 0 {
        eprintln!("lost SIGURG at sigsuspend on worker {i}");
        std::process::exit(96);
    }
    if after_r0 != 1 {
        BAD.fetch_add(1, Ordering::Relaxed);
    }
    unsafe {
        let mut cur_mask: libc::sigset_t = std::mem::zeroed();
        if libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut cur_mask) != 0
            || libc::sigismember(&cur_mask, libc::SIGURG) != 1
        {
            BAD.fetch_add(1, Ordering::Relaxed);
        }
        if libc::pthread_sigmask(libc::SIG_SETMASK, &base_mask, std::ptr::null_mut()) != 0 {
            BAD.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Interrupted syscall results must survive signal delivery parks.
    let mut rbuf = [0u8; 7];
    while !STOP.load(Ordering::Acquire) {
        if unsafe { libc::getgid() } != expected_gid {
            BAD.fetch_add(1, Ordering::Relaxed);
        }
        if unsafe { libc::write(spipe[1], PIPE_MSG.as_ptr().cast(), PIPE_MSG.len()) }
            != PIPE_MSG.len() as isize
        {
            BAD.fetch_add(1, Ordering::Relaxed);
        }
        if unsafe { libc::read(spipe[0], rbuf.as_mut_ptr().cast(), rbuf.len()) }
            != rbuf.len() as isize
            || &rbuf != PIPE_MSG
        {
            BAD.fetch_add(1, Ordering::Relaxed);
        }
        if unsafe { libc::sched_yield() } != 0 {
            BAD.fetch_add(1, Ordering::Relaxed);
        }
    }
    unsafe {
        libc::close(spipe[0]);
        libc::close(spipe[1]);
    }
    std::ptr::null_mut()
}

fn main() {
    println!(
        "source_sha256={}",
        option_env!("CARRICK_SIGNAL_UNTOUCHED_ALTSTACK_SOURCE_SHA256").unwrap_or("unbound")
    );

    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = handler as *const () as usize;
        act.sa_flags = libc::SA_ONSTACK | libc::SA_SIGINFO | libc::SA_RESTART;
        libc::sigemptyset(&mut act.sa_mask);
        if libc::sigaction(libc::SIGURG, &act, std::ptr::null_mut()) != 0 {
            eprintln!("sigaction failed: errno={}", errno());
            std::process::exit(90);
        }

        let mut ready_rd = [-1i32; THREADS];
        let mut go_wr = [-1i32; THREADS];
        let mut ack_rd = [-1i32; THREADS];
        for i in 0..THREADS {
            let mut rfds = [-1i32; 2];
            let mut gfds = [-1i32; 2];
            let mut afds = [-1i32; 2];
            if libc::pipe(rfds.as_mut_ptr()) != 0
                || libc::pipe(gfds.as_mut_ptr()) != 0
                || libc::pipe(afds.as_mut_ptr()) != 0
            {
                eprintln!("pipe failed: errno={}", errno());
                std::process::exit(91);
            }
            ready_rd[i] = rfds[0];
            READY_WR[i].store(rfds[1], Ordering::Release);
            GO_RD[i].store(gfds[0], Ordering::Release);
            go_wr[i] = gfds[1];
            ack_rd[i] = afds[0];
            ACK_WR[i].store(afds[1], Ordering::Release);
        }

        let mut threads = [0 as libc::pthread_t; THREADS];
        for (i, slot) in threads.iter_mut().enumerate() {
            let rc = libc::pthread_create(slot, std::ptr::null(), worker, i as *mut libc::c_void);
            if rc != 0 {
                eprintln!("pthread_create failed: rc={rc}");
                std::process::exit(92);
            }
        }

        for (i, &rd) in ready_rd.iter().enumerate() {
            match wait_bytes::<5>(rd, 5000) {
                Ok(msg) if &msg == READY_MSG => {}
                Ok(other) => {
                    eprintln!("worker {i} reported unexpected ready bytes: {other:?}");
                    std::process::exit(93);
                }
                Err(code) => {
                    eprintln!("worker {i} did not become ready");
                    std::process::exit(code);
                }
            }
        }

        // Send one checked signal per worker per round and require one
        // acknowledged handler execution before sending the next signal to
        // that worker. Round 0 queues SIGURG while masked and unblocks via
        // sigsuspend on the untouched alternate stack.
        for r in 0..ROUNDS {
            for i in 0..THREADS {
                let before = HITS[i].load(Ordering::Acquire);
                if before != r {
                    eprintln!("worker {i} hit count {before} != {r} before send");
                    std::process::exit(95);
                }
                let target = WORKER_PTHREAD[i].load(Ordering::Acquire) as libc::pthread_t;
                let krc = libc::pthread_kill(target, libc::SIGURG);
                if krc != 0 {
                    eprintln!("pthread_kill failed: rc={krc}");
                    std::process::exit(97);
                }
                if r == 0
                    && libc::write(go_wr[i], GO_MSG.as_ptr().cast(), GO_MSG.len())
                        != GO_MSG.len() as isize
                {
                    eprintln!("failed writing go message to worker {i}");
                    std::process::exit(95);
                }
                if let Err(code) = wait_bytes::<1>(ack_rd[i], 5000) {
                    eprintln!("lost SIGURG on worker {i} round {r}");
                    std::process::exit(code);
                }
                let after = HITS[i].load(Ordering::Acquire);
                if after != r + 1 {
                    eprintln!("worker {i} hit count {after} != {} after send", r + 1);
                    std::process::exit(95);
                }
                if BAD.load(Ordering::Acquire) != 0 {
                    eprintln!("invariant failure in worker or handler");
                    std::process::exit(95);
                }
            }
        }

        STOP.store(true, Ordering::Release);
        for t in threads {
            if libc::pthread_join(t, std::ptr::null_mut()) != 0 {
                eprintln!("pthread_join failed");
                std::process::exit(94);
            }
        }
        if BAD.load(Ordering::Acquire) != 0 {
            eprintln!("invariant failure after join");
            std::process::exit(95);
        }
        for (i, slot) in HITS.iter().enumerate() {
            let count = slot.load(Ordering::Acquire);
            if count != ROUNDS {
                eprintln!("worker {i} total hits {count} != {ROUNDS}");
                std::process::exit(96);
            }
        }

        for i in 0..THREADS {
            let lo = ALT_LO[i].load(Ordering::Acquire);
            if lo != 0 {
                libc::munmap(lo as *mut libc::c_void, ALT);
            }
            libc::close(ready_rd[i]);
            libc::close(READY_WR[i].load(Ordering::Acquire));
            libc::close(GO_RD[i].load(Ordering::Acquire));
            libc::close(go_wr[i]);
            libc::close(ack_rd[i]);
            libc::close(ACK_WR[i].load(Ordering::Acquire));
        }
    }

    println!("threads={THREADS}");
    println!("rounds={ROUNDS}");
    println!("untouched_altstack_ok=true");
}
