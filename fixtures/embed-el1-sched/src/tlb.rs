//! TLB-maintenance witnesses (contract `kernel.mm.tlb-maintenance-budget`).
//!
//! - `tlb-edit-budget <rounds>`: a running thread of a two-thread MM
//!   restricts, restores and retires one touched private page of this
//!   executable each round (`mprotect` RO, `mprotect` RW, `munmap`, `mmap`
//!   again): host-edited, three required invalidations per round. The test
//!   reads their cost as a slope against `rounds`.
//!   The sibling acknowledges completed runtime initialization before editing.
//!   A reserved window bounds the unmapped hole to one page. Optional
//!   `force-gap-allocation` requests a 16 KiB sibling allocation inside that
//!   gap to prove an alternate-stack-sized allocation cannot consume it.
//! - `tlb-stale-threads <rounds> <workers>`: `workers` threads pinned to
//!   guest CPUs `1..=workers` keep one page hot while the main thread (CPU 0)
//!   `mprotect`s it read-only and later `munmap`s it. Every worker's next
//!   write (after the `mprotect`) and next read (after the `munmap`) must
//!   fault. A probe is one instruction the SIGSEGV handler steps over, so
//!   all workers probe the same page at once.
//! - `tlb-fork-stale <rounds>`: a worker on CPU 1 keeps a page hot and
//!   writable; the main thread forks; once `fork` has returned the worker
//!   writes a new value, and the child must still read the value from
//!   before the fork.
//! - `tlb-exec-stale`: a worker on CPU 1 keeps a page hot; the main thread
//!   `munmap`s it and `execve`s; the new image maps the same address and a
//!   worker on CPU 1 must read zero there.
//!
//! Every wait is bounded, so a lost wake is a failed line, not a hang.

use std::cell::Cell;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use super::{futex_wait_timeout, futex_wake, pin, wait_until_changed};

const MAX_WORKERS: usize = 7;
const PAGE: usize = 4096;
const READ_SENTINEL: u64 = 0x5E17_14E1_5E17_14E1;

static PROBE_PAGE: AtomicUsize = AtomicUsize::new(0);
static CMD: AtomicU32 = AtomicU32::new(0);
static ACKS: AtomicU32 = AtomicU32::new(0);
static FAULTS: [AtomicU64; MAX_WORKERS] = [const { AtomicU64::new(0) }; MAX_WORKERS];
static STALE: AtomicU64 = AtomicU64::new(0);
static ERRORS: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static WORKER: Cell<usize> = const { Cell::new(usize::MAX) };
}

const OP_WARM: u32 = 1;
const OP_WRITE_PROBE: u32 = 2;
const OP_READ_PROBE: u32 = 3;
const OP_STOP: u32 = 4;
const OP_WRITE_NEW: u32 = 5;
const OP_READ_VALUE: u32 = 6;

static WORKER_SEEN: AtomicU64 = AtomicU64::new(u64::MAX);

/// SIGSEGV on a worker's probe: count it and step over the one-instruction
/// probe, so a read probe returns its sentinel and a write probe stores
/// nothing.
extern "C" fn on_probe_segv(sig: libc::c_int, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    if sig != libc::SIGSEGV || info.is_null() || ctx.is_null() {
        unsafe { libc::_exit(71) };
    }
    let worker = WORKER.with(Cell::get);
    let page = PROBE_PAGE.load(Ordering::SeqCst);
    let fault = unsafe { (*info).si_addr() as usize };
    if worker >= MAX_WORKERS || page == 0 || fault & !(PAGE - 1) != page {
        unsafe { libc::_exit(72) };
    }
    FAULTS[worker].fetch_add(1, Ordering::SeqCst);
    let context = ctx.cast::<libc::ucontext_t>();
    unsafe { (*context).uc_mcontext.pc += 4 };
}

fn install_probe_handler() -> bool {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = on_probe_segv as *const () as usize;
    action.sa_flags = libc::SA_SIGINFO;
    unsafe { libc::sigemptyset(&mut action.sa_mask) };
    unsafe { libc::sigaction(libc::SIGSEGV, &action, std::ptr::null_mut()) == 0 }
}

/// One `str`: the handler steps over it when it faults.
#[inline(never)]
fn probe_write(ptr: *mut u64, value: u64) {
    unsafe {
        std::arch::asm!("str {v}, [{p}]", p = in(reg) ptr, v = in(reg) value, options(nostack));
    }
}

/// One `ldr`: a faulting load leaves [`READ_SENTINEL`] in place.
#[inline(never)]
fn probe_read(ptr: *const u64) -> u64 {
    let mut value = READ_SENTINEL;
    unsafe {
        std::arch::asm!(
            "ldr {v}, [{p}]",
            p = in(reg) ptr,
            v = inout(reg) value,
            options(nostack, readonly)
        );
    }
    value
}

/// Post `op` to every worker and wait (bounded) until each acknowledged.
fn command(op: u32, workers: u32) -> bool {
    let target = ACKS.load(Ordering::SeqCst).wrapping_add(workers);
    let seq = (CMD.load(Ordering::SeqCst) >> 8).wrapping_add(1);
    CMD.store((seq << 8) | op, Ordering::SeqCst);
    let _ = futex_wake(&CMD, u32::MAX >> 1);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let acks = ACKS.load(Ordering::SeqCst);
        if acks == target {
            return true;
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return false;
        }
        let _ = wait_until_changed(&ACKS, acks, deadline - now);
    }
}

/// A worker pinned to guest CPU `cpu`, serving commands until `OP_STOP`.
fn spawn_worker(index: usize, cpu: u32) -> std::thread::JoinHandle<()> {
    // Read before the thread exists: a command posted before it first runs
    // must still be served, not taken as already seen.
    let first_seen = CMD.load(Ordering::SeqCst);
    std::thread::spawn(move || {
        WORKER.with(|worker| worker.set(index));
        if pin(cpu) != 0 {
            ERRORS.fetch_add(1, Ordering::SeqCst);
        }
        let mut seen = first_seen;
        loop {
            while CMD.load(Ordering::SeqCst) == seen {
                let _ = futex_wait_timeout(&CMD, seen, Duration::from_millis(50));
            }
            let cmd = CMD.load(Ordering::SeqCst);
            seen = cmd;
            let ptr = PROBE_PAGE.load(Ordering::SeqCst) as *mut u64;
            let before = FAULTS[index].load(Ordering::SeqCst);
            match cmd & 0xff {
                OP_WARM => {
                    for i in 0..64u64 {
                        unsafe { std::ptr::write_volatile(ptr.add(1 + index), 0x5A5A_0000 + i) };
                        let _ = unsafe { std::ptr::read_volatile(ptr) };
                    }
                }
                OP_WRITE_PROBE => {
                    probe_write(ptr.wrapping_add(1 + index), 0xC0DE);
                    if FAULTS[index].load(Ordering::SeqCst) == before {
                        // Written through a stale writable translation.
                        STALE.fetch_add(1, Ordering::SeqCst);
                    }
                }
                OP_READ_PROBE => {
                    let value = probe_read(ptr);
                    if FAULTS[index].load(Ordering::SeqCst) == before || value != READ_SENTINEL {
                        // Read through a stale translation of the unmapped page.
                        STALE.fetch_add(1, Ordering::SeqCst);
                    }
                }
                OP_WRITE_NEW => unsafe { std::ptr::write_volatile(ptr, 0x4E45_5700) },
                OP_READ_VALUE => {
                    WORKER_SEEN.store(unsafe { std::ptr::read_volatile(ptr) }, Ordering::SeqCst);
                }
                _ => {
                    ACKS.fetch_add(1, Ordering::SeqCst);
                    let _ = futex_wake(&ACKS, 1);
                    return;
                }
            }
            ACKS.fetch_add(1, Ordering::SeqCst);
            let _ = futex_wake(&ACKS, 1);
        }
    })
}

/// Map one RW anonymous page, anywhere or exactly at `at`, which the caller
/// has just unmapped: MAP_FIXED, so a lagging release of the old range
/// cannot fail it with EEXIST and blur the TLB witness.
fn map_page(at: usize) -> usize {
    let flags = libc::MAP_PRIVATE
        | libc::MAP_ANONYMOUS
        | if at == 0 { 0 } else { libc::MAP_FIXED };
    let page = unsafe {
        libc::mmap(
            at as *mut libc::c_void,
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            flags,
            -1,
            0,
        )
    };
    if page == libc::MAP_FAILED || (at != 0 && page as usize != at) {
        0
    } else {
        page as usize
    }
}

/// One private page of `fd` at file offset 0, anywhere or exactly at `at`.
fn map_file_page(fd: libc::c_int, at: usize) -> usize {
    let flags = libc::MAP_PRIVATE | if at == 0 { 0 } else { libc::MAP_FIXED };
    let page = unsafe {
        libc::mmap(
            at as *mut libc::c_void,
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            flags,
            fd,
            0,
        )
    };
    if page == libc::MAP_FAILED || (at != 0 && page as usize != at) {
        0
    } else {
        page as usize
    }
}

/// `tlb-edit-budget <rounds>`: the edited page is a private mapping of this
/// executable, which the host maps and edits (anonymous memory may be served
/// by EL1 in-zone, which never needs a host round trip to begin with).
pub(crate) fn edit_budget(exe: &str, rounds: usize, force_gap_allocation: bool) -> i32 {
    if rounds == 0 || rounds > 10_000 {
        println!("tlb-edit-budget invalid rounds={rounds}");
        return 1;
    }
    unsafe { libc::alarm(90) };
    // Keep the edited 4 KiB page inside a reserved window. Its transient
    // munmap hole cannot fit a sibling's 16 KiB alternate signal stack:
    // neither adjacent reservation may be consumed by an ordinary mmap.
    const WINDOW_BYTES: usize = 16 * PAGE;
    let window = unsafe {
        libc::mmap(
            std::ptr::null_mut(), WINDOW_BYTES, libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0,
        )
    };
    if window == libc::MAP_FAILED {
        println!("tlb-edit-budget private window reservation failed");
        return 1;
    }
    let private_page = window as usize + 8 * PAGE;
    // A second thread makes this a multi-threaded MM; it stays parked.
    static PARKED: AtomicU32 = AtomicU32::new(0);
    static READY: AtomicU32 = AtomicU32::new(0);
    static ALLOCATED: AtomicU32 = AtomicU32::new(0);
    static SIBLING_REGION: AtomicUsize = AtomicUsize::new(0);
    static SIBLING_ERROR: AtomicU32 = AtomicU32::new(0);
    const SIBLING_BYTES: usize = 4 * PAGE;
    let sibling = std::thread::spawn(|| {
        // Rust's alternate signal stack and guard are initialized before
        // this closure. Do not start editing until that initialization ends.
        READY.store(1, Ordering::Release);
        let _ = futex_wake(&READY, 1);
        while PARKED.load(Ordering::Acquire) != 1 {
            if PARKED.load(Ordering::Acquire) == 2 {
                let region = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(), SIBLING_BYTES,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0,
                    )
                };
                let address = if region == libc::MAP_FAILED { usize::MAX } else {
                    unsafe { std::ptr::write_volatile(region.cast::<u64>(), 0x51b11a6) };
                    region as usize
                };
                SIBLING_REGION.store(address, Ordering::Release);
                let _ = PARKED.compare_exchange(2, 0, Ordering::AcqRel, Ordering::Acquire);
                ALLOCATED.store(1, Ordering::Release);
                let _ = futex_wake(&ALLOCATED, 1);
            }
            let _ = futex_wait_timeout(&PARKED, 0, Duration::from_secs(1));
        }
        let address = SIBLING_REGION.load(Ordering::Acquire);
        if address != 0 && address != usize::MAX
            && unsafe { libc::munmap(address as *mut libc::c_void, SIBLING_BYTES) } != 0
        {
            SIBLING_ERROR.store(1, Ordering::Release);
        }
    });
    if !wait_until_changed(&READY, 0, Duration::from_secs(5)) {
        PARKED.store(1, Ordering::Release);
        let _ = futex_wake(&PARKED, 1);
        println!("tlb-edit-budget sibling initialization timed out");
        return 1;
    }
    let path = std::ffi::CString::new(exe).expect("exe path");
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
    let base = if fd < 0 { 0 } else { map_file_page(fd, private_page) };
    if base == 0 {
        PARKED.store(1, Ordering::Release);
        let _ = futex_wake(&PARKED, 1);
        println!("tlb-edit-budget map {exe} failed");
        return 1;
    }
    let ptr = base as *mut u64;
    // The file's first word (the ELF identification).
    let original = unsafe { std::ptr::read_volatile(ptr) };
    let mut errors = 0u64;
    let mut first_error = String::new();
    let mut fail = |what: String| {
        if errors == 0 {
            first_error = what;
        }
        errors += 1;
    };
    unsafe { std::ptr::write_volatile(ptr, 1) };
    for round in 0..rounds as u64 {
        let region = base as *mut libc::c_void;
        if unsafe { libc::mprotect(region, PAGE, libc::PROT_READ) } != 0 {
            fail(format!("mprotect-ro round={round} {}", std::io::Error::last_os_error()));
        }
        let _ = unsafe { std::ptr::read_volatile(ptr) };
        if unsafe { libc::mprotect(region, PAGE, libc::PROT_READ | libc::PROT_WRITE) } != 0 {
            fail(format!("mprotect-rw round={round} {}", std::io::Error::last_os_error()));
        }
        unsafe { std::ptr::write_volatile(ptr, round + 2) };
        if unsafe { libc::munmap(region, PAGE) } != 0 {
            fail(format!("munmap round={round} {}", std::io::Error::last_os_error()));
            break;
        }
        if force_gap_allocation && round == 0 {
            PARKED.store(2, Ordering::Release);
            let _ = futex_wake(&PARKED, 1);
            if !wait_until_changed(&ALLOCATED, 0, Duration::from_secs(5)) {
                fail("sibling gap allocation timed out".to_owned());
                break;
            }
            if SIBLING_REGION.load(Ordering::Acquire) == usize::MAX {
                fail("sibling gap allocation failed".to_owned());
                break;
            }
        }
        if map_file_page(fd, base) != base {
            fail(format!("remap round={round} {}", std::io::Error::last_os_error()));
            break;
        }
        // A fresh private copy: the file's bytes, never this round's store.
        let seen = unsafe { std::ptr::read_volatile(ptr) };
        if seen != original {
            fail(format!("stale round={round} value={seen:#x} file={original:#x}"));
        }
        unsafe { std::ptr::write_volatile(ptr, round + 3) };
    }
    unsafe { libc::close(fd) };
    PARKED.store(1, Ordering::SeqCst);
    let _ = futex_wake(&PARKED, 1);
    let _ = sibling.join();
    if SIBLING_ERROR.load(Ordering::Acquire) != 0 {
        fail("sibling gap retirement failed".to_owned());
    }
    if unsafe { libc::munmap(window, WINDOW_BYTES) } != 0 {
        fail("private window retirement failed".to_owned());
    }
    let sibling_region = SIBLING_REGION.load(Ordering::Acquire);
    let overlaps = sibling_region != 0 && sibling_region != usize::MAX
        && base < sibling_region + SIBLING_BYTES && sibling_region < base + PAGE;
    println!("tlb-edit-budget forced_gap={force_gap_allocation} sibling_gap_overlaps={overlaps}");
    println!(
        "tlb-edit-budget rounds={rounds} errors={errors} ok={} {first_error}",
        errors == 0
    );
    i32::from(errors != 0)
}

/// `tlb-stale-threads <rounds> <workers>`.
pub(crate) fn stale_threads(rounds: usize, workers: usize) -> i32 {
    if rounds == 0 || rounds > 10_000 || workers == 0 || workers > MAX_WORKERS {
        println!("tlb-stale-threads invalid rounds={rounds} workers={workers}");
        return 1;
    }
    unsafe { libc::alarm(90) };
    if !install_probe_handler() || pin(0) != 0 {
        println!("tlb-stale-threads setup failed");
        return 1;
    }
    let base = map_page(0);
    if base == 0 {
        println!("tlb-stale-threads mmap failed");
        return 1;
    }
    PROBE_PAGE.store(base, Ordering::SeqCst);
    let handles: Vec<_> = (0..workers)
        .map(|index| spawn_worker(index, index as u32 + 1))
        .collect();
    let count = workers as u32;
    let mut timeouts = 0u64;
    let mut zero_failures = 0u64;
    for _ in 0..rounds {
        let region = base as *mut libc::c_void;
        timeouts += u64::from(!command(OP_WARM, count));
        if unsafe { libc::mprotect(region, PAGE, libc::PROT_READ) } != 0 {
            ERRORS.fetch_add(1, Ordering::SeqCst);
        }
        timeouts += u64::from(!command(OP_WRITE_PROBE, count));
        if unsafe { libc::mprotect(region, PAGE, libc::PROT_READ | libc::PROT_WRITE) } != 0 {
            ERRORS.fetch_add(1, Ordering::SeqCst);
        }
        timeouts += u64::from(!command(OP_WARM, count));
        if unsafe { libc::munmap(region, PAGE) } != 0 {
            ERRORS.fetch_add(1, Ordering::SeqCst);
        }
        timeouts += u64::from(!command(OP_READ_PROBE, count));
        if map_page(base) != base {
            ERRORS.fetch_add(1, Ordering::SeqCst);
            break;
        }
        // A fresh page: nothing a worker wrote before the munmap survives.
        for word in 0..PAGE / 8 {
            if unsafe { std::ptr::read_volatile((base as *const u64).add(word)) } != 0 {
                zero_failures += 1;
            }
        }
    }
    timeouts += u64::from(!command(OP_STOP, count));
    for handle in handles {
        let _ = handle.join();
    }
    let expected = 2 * rounds as u64;
    let faults: Vec<u64> = FAULTS[..workers]
        .iter()
        .map(|faults| faults.load(Ordering::SeqCst))
        .collect();
    let stale = STALE.load(Ordering::SeqCst);
    let errors = ERRORS.load(Ordering::SeqCst) + zero_failures;
    let ok = faults.iter().all(|&f| f == expected) && stale == 0 && errors == 0 && timeouts == 0;
    println!(
        "tlb-stale-threads rounds={rounds} workers={workers} expected_faults={expected} \
         faults={faults:?} stale={stale} errors={errors} timeouts={timeouts} ok={ok}"
    );
    i32::from(!ok)
}

/// `tlb-fork-stale <rounds>`.
pub(crate) fn fork_stale(rounds: usize) -> i32 {
    if rounds == 0 || rounds > 1_000 {
        println!("tlb-fork-stale invalid rounds={rounds}");
        return 1;
    }
    unsafe { libc::alarm(90) };
    if pin(0) != 0 {
        println!("tlb-fork-stale pin failed");
        return 1;
    }
    let base = map_page(0);
    if base == 0 {
        println!("tlb-fork-stale mmap failed");
        return 1;
    }
    PROBE_PAGE.store(base, Ordering::SeqCst);
    let worker = spawn_worker(0, 1);
    let ptr = base as *mut u64;
    let mut child_failures = 0u64;
    let mut parent_failures = 0u64;
    let mut timeouts = 0u64;
    for round in 0..rounds as u64 {
        let old = 0x01D0_0000 + round;
        unsafe { std::ptr::write_volatile(ptr, old) };
        // The worker's TLB now holds a writable translation of the page.
        timeouts += u64::from(!command(OP_WARM, 1));
        let mut go = [0i32; 2];
        if unsafe { libc::pipe(go.as_mut_ptr()) } != 0 {
            ERRORS.fetch_add(1, Ordering::SeqCst);
            break;
        }
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // Child: wait for the parent's post-fork write, then read.
            let mut byte = 0u8;
            unsafe {
                libc::close(go[1]);
                libc::read(go[0], (&mut byte as *mut u8).cast(), 1);
                let seen = std::ptr::read_volatile(ptr);
                libc::_exit(if seen == old { 0 } else { 9 });
            }
        }
        unsafe { libc::close(go[0]) };
        if pid < 0 {
            ERRORS.fetch_add(1, Ordering::SeqCst);
            unsafe { libc::close(go[1]) };
            break;
        }
        // After fork returned: the worker writes through whatever
        // translation its vCPU holds. A stale writable one would land in the
        // frame the child shares.
        timeouts += u64::from(!command(OP_WRITE_NEW, 1));
        if unsafe { std::ptr::read_volatile(ptr) } != 0x4E45_5700 {
            parent_failures += 1;
        }
        unsafe {
            libc::write(go[1], b"g".as_ptr().cast(), 1);
            libc::close(go[1]);
        }
        let mut status = 0;
        if unsafe { libc::waitpid(pid, &mut status, 0) } != pid
            || !libc::WIFEXITED(status)
            || libc::WEXITSTATUS(status) != 0
        {
            child_failures += 1;
        }
    }
    timeouts += u64::from(!command(OP_STOP, 1));
    let _ = worker.join();
    let errors = ERRORS.load(Ordering::SeqCst);
    let ok = child_failures == 0 && parent_failures == 0 && errors == 0 && timeouts == 0;
    println!(
        "tlb-fork-stale rounds={rounds} child_failures={child_failures} \
         parent_failures={parent_failures} errors={errors} timeouts={timeouts} ok={ok}"
    );
    i32::from(!ok)
}

/// `tlb-exec-stale`: the pre-exec half.
pub(crate) fn exec_stale(argv0: &str) -> i32 {
    unsafe { libc::alarm(90) };
    if pin(0) != 0 {
        println!("tlb-exec-stale pin failed");
        return 1;
    }
    let base = map_page(0);
    if base == 0 {
        println!("tlb-exec-stale mmap failed");
        return 1;
    }
    PROBE_PAGE.store(base, Ordering::SeqCst);
    unsafe { std::ptr::write_volatile(base as *mut u64, 0xE1E1_E1E1) };
    let worker = spawn_worker(0, 1);
    if !command(OP_WARM, 1) {
        println!("tlb-exec-stale warm timed out");
        return 1;
    }
    // The worker stays alive (parked) on CPU 1 until execve ends it.
    drop(worker);
    if unsafe { libc::munmap(base as *mut libc::c_void, PAGE) } != 0 {
        println!("tlb-exec-stale munmap failed");
        return 1;
    }
    let path = std::ffi::CString::new(argv0).expect("argv0");
    let arg0 = std::ffi::CString::new("el1-sched").expect("arg0");
    let arg1 = std::ffi::CString::new("tlb-exec-stale-child").expect("arg1");
    let arg2 = std::ffi::CString::new(format!("{base:x}")).expect("arg2");
    let argv = [
        arg0.as_ptr(),
        arg1.as_ptr(),
        arg2.as_ptr(),
        std::ptr::null(),
    ];
    let envp = [std::ptr::null::<libc::c_char>()];
    let rc = unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    println!("tlb-exec-stale execve failed rc={rc}");
    1
}

/// `tlb-exec-stale-child <hex address>`: the post-exec half.
pub(crate) fn exec_stale_child(address: Option<&str>) -> i32 {
    let Some(base) = address.and_then(|a| usize::from_str_radix(a, 16).ok()) else {
        println!("tlb-exec-stale child missing address");
        return 1;
    };
    if !install_probe_handler() || pin(0) != 0 {
        println!("tlb-exec-stale child setup failed");
        return 1;
    }
    // Unmapped in the new image: a read on CPU 1 must fault.
    PROBE_PAGE.store(base, Ordering::SeqCst);
    let worker = spawn_worker(0, 1);
    let mut stale_reads = 0u64;
    let mut timeouts = u64::from(!command(OP_READ_PROBE, 1));
    stale_reads += STALE.swap(0, Ordering::SeqCst);
    // The probe faulted, so nothing of the new image lives there: map it
    // back with MAP_FIXED.
    let mapped = unsafe {
        libc::mmap(
            base as *mut libc::c_void,
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    if FAULTS[0].load(Ordering::SeqCst) != 1 || mapped as usize != base {
        println!(
            "tlb-exec-stale child cannot map 0x{base:x}: faults={} mapped={mapped:?} errno={}",
            FAULTS[0].load(Ordering::SeqCst),
            std::io::Error::last_os_error()
        );
        return 1;
    }
    // Mapped fresh: CPU 1 must see zero, never the old image's value.
    timeouts += u64::from(!command(OP_READ_VALUE, 1));
    let seen = WORKER_SEEN.load(Ordering::SeqCst);
    let zero = seen == 0;
    timeouts += u64::from(!command(OP_STOP, 1));
    let _ = worker.join();
    let faults = FAULTS[0].load(Ordering::SeqCst);
    let errors = ERRORS.load(Ordering::SeqCst);
    let ok = faults == 1 && stale_reads == 0 && zero && errors == 0 && timeouts == 0;
    println!(
        "tlb-exec-stale faults={faults} stale_reads={stale_reads} seen={seen:#x} errors={errors} \
         timeouts={timeouts} ok={ok}"
    );
    i32::from(!ok)
}
