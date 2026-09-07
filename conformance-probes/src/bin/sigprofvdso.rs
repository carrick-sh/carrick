//! SIGPROF samples inside the vDSO.
//!
//! When an interval timer (ITIMER_PROF) or a per-thread CPU-clock timer
//! (`timer_create(CLOCK_THREAD_CPUTIME_ID, SIGEV_THREAD_ID, SIGPROF)`) is armed
//! while the thread is executing a tight loop calling `clock_gettime` (a vDSO function
//! with no syscalls), the vCPU must be interrupted asynchronously at its real guest PC.
//! The signal handler's `ucontext.uc_mcontext.pc` must reflect the interrupted PC:
//! samples should land both in the vDSO image and in the probe's own text.
//!
//! Expected Linux output:
//! ```text
//! sigprof_fired=1
//! sigprof_pc_in_vdso=1
//! sigprof_pc_in_text=1
//! sigprof_after_disarm=0
//! timer_fired=1
//! timer_pc_in_vdso=1
//! timer_pc_in_text=1
//! timer_after_disarm=0
//! ```

use std::sync::atomic::{AtomicU32, Ordering};

const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_SYSINFO_EHDR: u64 = 33;
const PT_LOAD: u32 = 1;
const PT_PHDR: u32 = 6;
const PF_X: u32 = 1;

static SIGPROF_HITS: AtomicU32 = AtomicU32::new(0);
static SIGPROF_VDSO_HITS: AtomicU32 = AtomicU32::new(0);
static SIGPROF_TEXT_HITS: AtomicU32 = AtomicU32::new(0);

const MAX_TEXT_RANGES: usize = 8;
static mut VDSO_RANGE: (u64, u64) = (0, 0);
static mut TEXT_RANGES: [(u64, u64); MAX_TEXT_RANGES] = [(0, 0); MAX_TEXT_RANGES];
static mut TEXT_RANGE_COUNT: usize = 0;

#[cfg(target_arch = "aarch64")]
#[repr(C)]
struct Aarch64SigContext {
    fault_address: u64,
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
}

unsafe fn ucontext_pc(ucontext: *mut libc::c_void) -> u64 {
    let uc = ucontext as *const libc::ucontext_t;
    #[cfg(target_arch = "aarch64")]
    {
        let mc = &(*uc).uc_mcontext as *const _ as *const Aarch64SigContext;
        (*mc).pc
    }
    #[cfg(target_arch = "x86_64")]
    {
        (*uc).uc_mcontext.gregs[libc::REG_RIP as usize] as u64
    }
}

unsafe fn is_in_vdso(pc: u64) -> bool {
    pc >= VDSO_RANGE.0 && pc < VDSO_RANGE.1
}

unsafe fn is_in_text(pc: u64) -> bool {
    for i in 0..TEXT_RANGE_COUNT {
        let (start, end) = TEXT_RANGES[i];
        if pc >= start && pc < end {
            return true;
        }
    }
    false
}

extern "C" fn on_sigprof(_sig: i32, _info: *mut libc::siginfo_t, ucontext: *mut libc::c_void) {
    let pc = unsafe { ucontext_pc(ucontext) };
    SIGPROF_HITS.fetch_add(1, Ordering::SeqCst);
    if unsafe { is_in_vdso(pc) } {
        SIGPROF_VDSO_HITS.fetch_add(1, Ordering::SeqCst);
    }
    if unsafe { is_in_text(pc) } {
        SIGPROF_TEXT_HITS.fetch_add(1, Ordering::SeqCst);
    }
}

unsafe fn init_ranges() {
    let base = libc::getauxval(AT_SYSINFO_EHDR);
    if base != 0 {
        let e_phoff = *((base + 0x20) as *const u64);
        let e_phentsize = *((base + 0x36) as *const u16) as u64;
        let e_phnum = *((base + 0x38) as *const u16) as u64;

        let mut start = u64::MAX;
        let mut end = 0u64;
        for i in 0..e_phnum {
            let ph = base + e_phoff + i * e_phentsize;
            let p_type = *(ph as *const u32);
            if p_type == PT_LOAD {
                let p_vaddr = *((ph + 16) as *const u64);
                let p_memsz = *((ph + 40) as *const u64);
                let seg_start = base + p_vaddr;
                let seg_end = seg_start + p_memsz;
                if seg_start < start {
                    start = seg_start;
                }
                if seg_end > end {
                    end = seg_end;
                }
            }
        }
        if start < end {
            VDSO_RANGE = (start, end);
        }
    }

    let phdr = libc::getauxval(AT_PHDR);
    let phnum = libc::getauxval(AT_PHNUM);
    let phent = libc::getauxval(AT_PHENT);
    if phdr != 0 && phnum != 0 && phent >= 56 {
        let mut load_base = None;
        for i in 0..phnum {
            let ph = phdr + i * phent;
            let p_type = *(ph as *const u32);
            if p_type == PT_PHDR {
                let p_vaddr = *((ph + 16) as *const u64);
                load_base = Some(phdr.wrapping_sub(p_vaddr));
                break;
            }
        }
        let base = load_base.unwrap_or(0);
        for i in 0..phnum {
            let ph = phdr + i * phent;
            let p_type = *(ph as *const u32);
            let p_flags = *((ph + 4) as *const u32);
            if p_type == PT_LOAD && (p_flags & PF_X) != 0 {
                let p_vaddr = *((ph + 16) as *const u64);
                let p_memsz = *((ph + 40) as *const u64);
                if TEXT_RANGE_COUNT < MAX_TEXT_RANGES {
                    TEXT_RANGES[TEXT_RANGE_COUNT] = (base + p_vaddr, base + p_vaddr + p_memsz);
                    TEXT_RANGE_COUNT += 1;
                }
            }
        }
    }
}

#[inline(never)]
fn spin_clock_gettime(duration_ms: u64) {
    let mut start = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut start) };
    let start_ns = (start.tv_sec as u64) * 1_000_000_000 + (start.tv_nsec as u64);
    let target_ns = duration_ms * 1_000_000;

    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    loop {
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
        let cur_ns = (now.tv_sec as u64) * 1_000_000_000 + (now.tv_nsec as u64);
        if cur_ns.saturating_sub(start_ns) >= target_ns {
            break;
        }
    }
}

fn test_itimer() {
    SIGPROF_HITS.store(0, Ordering::SeqCst);
    SIGPROF_VDSO_HITS.store(0, Ordering::SeqCst);
    SIGPROF_TEXT_HITS.store(0, Ordering::SeqCst);

    let it = libc::itimerval {
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 1000,
        },
        it_value: libc::timeval {
            tv_sec: 0,
            tv_usec: 1000,
        },
    };
    unsafe { libc::setitimer(libc::ITIMER_PROF, &it, std::ptr::null_mut()) };

    spin_clock_gettime(300);

    let zero = libc::itimerval {
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
    };
    unsafe { libc::setitimer(libc::ITIMER_PROF, &zero, std::ptr::null_mut()) };

    let pre_disarm_hits = SIGPROF_HITS.load(Ordering::SeqCst);
    let pre_vdso = SIGPROF_VDSO_HITS.load(Ordering::SeqCst);
    let pre_text = SIGPROF_TEXT_HITS.load(Ordering::SeqCst);

    spin_clock_gettime(50);
    let post_disarm_hits = SIGPROF_HITS.load(Ordering::SeqCst);
    let after_disarm = post_disarm_hits.saturating_sub(pre_disarm_hits);

    let fired = u32::from(pre_disarm_hits >= 20);
    let pc_in_vdso = u32::from(pre_disarm_hits > 0 && pre_vdso * 100 >= pre_disarm_hits * 25);
    let pc_in_text = u32::from(pre_text > 0);

    println!("sigprof_fired={fired}");
    println!("sigprof_pc_in_vdso={pc_in_vdso}");
    println!("sigprof_pc_in_text={pc_in_text}");
    println!("sigprof_after_disarm={after_disarm}");
}

fn test_posix_timer() {
    SIGPROF_HITS.store(0, Ordering::SeqCst);
    SIGPROF_VDSO_HITS.store(0, Ordering::SeqCst);
    SIGPROF_TEXT_HITS.store(0, Ordering::SeqCst);

    let mut sev: libc::sigevent = unsafe { std::mem::zeroed() };
    sev.sigev_notify = 4; // SIGEV_THREAD_ID
    sev.sigev_signo = libc::SIGPROF;
    let tid: i32 = unsafe { libc::syscall(libc::SYS_gettid) as i32 };
    let sev_bytes = &mut sev as *mut _ as *mut u8;
    unsafe {
        std::ptr::copy_nonoverlapping(&tid as *const _ as *const u8, sev_bytes.add(16), 4);
    }

    let mut timer_id: libc::timer_t = std::ptr::null_mut();
    let create_rc =
        unsafe { libc::timer_create(libc::CLOCK_THREAD_CPUTIME_ID, &mut sev, &mut timer_id) };

    if create_rc != 0 {
        println!("timer_fired=0");
        println!("timer_pc_in_vdso=0");
        println!("timer_pc_in_text=0");
        println!("timer_after_disarm=0");
        return;
    }

    let spec = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        },
        it_value: libc::timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        },
    };
    let arm_rc =
        unsafe { libc::timer_settime(timer_id, 0, &spec, std::ptr::null_mut()) };
    if arm_rc != 0 {
        unsafe { libc::timer_delete(timer_id) };
        println!("timer_fired=0");
        println!("timer_pc_in_vdso=0");
        println!("timer_pc_in_text=0");
        println!("timer_after_disarm=0");
        return;
    }

    spin_clock_gettime(300);

    let disarm_spec = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };
    unsafe { libc::timer_settime(timer_id, 0, &disarm_spec, std::ptr::null_mut()) };

    let pre_disarm_hits = SIGPROF_HITS.load(Ordering::SeqCst);
    let pre_vdso = SIGPROF_VDSO_HITS.load(Ordering::SeqCst);
    let pre_text = SIGPROF_TEXT_HITS.load(Ordering::SeqCst);

    spin_clock_gettime(50);
    let post_disarm_hits = SIGPROF_HITS.load(Ordering::SeqCst);
    let after_disarm = post_disarm_hits.saturating_sub(pre_disarm_hits);

    unsafe { libc::timer_delete(timer_id) };

    let fired = u32::from(pre_disarm_hits >= 20);
    let pc_in_vdso = u32::from(pre_disarm_hits > 0 && pre_vdso * 100 >= pre_disarm_hits * 25);
    let pc_in_text = u32::from(pre_text > 0);

    println!("timer_fired={fired}");
    println!("timer_pc_in_vdso={pc_in_vdso}");
    println!("timer_pc_in_text={pc_in_text}");
    println!("timer_after_disarm={after_disarm}");
}

fn main() {
    unsafe {
        init_ranges();
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_sigprof as *const () as usize;
        sa.sa_flags = libc::SA_RESTART | libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGPROF, &sa, std::ptr::null_mut());
    }

    test_itimer();
    test_posix_timer();
}
