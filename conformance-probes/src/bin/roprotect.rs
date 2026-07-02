//! Read-only / PROT_NONE page-protection conformance: a guest store to a page
//! without PROT_WRITE (mmap'd PROT_READ, mprotect'd RW→R, or the binary's own
//! .rodata) must raise SIGSEGV with `si_code=SEGV_ACCERR` and `si_addr` = the
//! faulting VA; any access to a PROT_NONE mapping must fault too (Linux
//! reports ACCERR there as well — the VMA exists, the permission doesn't).
//! carrick historically let these writes silently succeed (guest PTEs carried
//! no real W bits for the image, and fault delivery was never exercised), so
//! guest .rodata was effectively writable — memory-safety-visible (Go
//! reflect TestTypeFieldReadOnly, runtime/debug TestSetPanicOnFault, LTP
//! mmap05).
//!
//! Recovery is mprotect-in-handler: the SIGSEGV handler records
//! (si_code, si_addr), flips the armed page to RW, and returns — the faulting
//! store re-runs and succeeds. Every phase is bounded: a handler that can't
//! fix the page _exits after 8 faults, and a phase that never faults simply
//! reports `*_faults=false` (no hang either way).

use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};

static FAULT_COUNT: AtomicUsize = AtomicUsize::new(0);
static LAST_CODE: AtomicI64 = AtomicI64::new(-1);
static LAST_ADDR: AtomicU64 = AtomicU64::new(0);
/// Page base the handler mprotects to RW to recover (0 = no recovery armed).
static FIX_PAGE: AtomicU64 = AtomicU64::new(0);
static FIX_LEN: AtomicU64 = AtomicU64::new(0);

const PAGE: usize = 4096;

extern "C" fn handler(_sig: i32, info: *mut libc::siginfo_t, _uc: *mut libc::c_void) {
    let n = FAULT_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
    unsafe {
        if n == 1 {
            LAST_ADDR.store((*info).si_addr() as u64, Ordering::SeqCst);
            LAST_CODE.store((*info).si_code as i64, Ordering::SeqCst);
        }
        // Bound: a recovery that doesn't take effect must not spin forever.
        if n > 8 {
            libc::_exit(3);
        }
        let page = FIX_PAGE.load(Ordering::SeqCst);
        let len = FIX_LEN.load(Ordering::SeqCst).max(PAGE as u64) as usize;
        if page == 0 {
            // A fault in a phase that must not fault: fail deterministically.
            libc::_exit(4);
        }
        libc::mprotect(
            page as *mut libc::c_void,
            len,
            libc::PROT_READ | libc::PROT_WRITE,
        );
    }
}

/// Arm a phase: reset fault bookkeeping and tell the handler which page to
/// make RW on fault.
fn arm(fix_page: u64, fix_len: usize) {
    FAULT_COUNT.store(0, Ordering::SeqCst);
    LAST_CODE.store(-1, Ordering::SeqCst);
    LAST_ADDR.store(0, Ordering::SeqCst);
    FIX_PAGE.store(fix_page, Ordering::SeqCst);
    FIX_LEN.store(fix_len as u64, Ordering::SeqCst);
}

fn faulted() -> bool {
    FAULT_COUNT.load(Ordering::SeqCst) > 0
}

fn report(tag: &str, expect_addr: u64) {
    let f = faulted();
    println!("{tag}_faults={f}");
    println!("{tag}_si_code={}", LAST_CODE.load(Ordering::SeqCst));
    println!(
        "{tag}_addr_match={}",
        LAST_ADDR.load(Ordering::SeqCst) == expect_addr
    );
}

fn mmap_anon(len: usize, prot: i32) -> *mut u8 {
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            prot,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        println!("mmap FAIL");
        unsafe { libc::_exit(2) };
    }
    p as *mut u8
}

/// 2 pages of genuinely read-only image data: big enough that at least one
/// whole page lies inside .rodata regardless of where the section starts.
static RODATA: [u64; 1024] = [0x5245_4144_4f4e_4c59; 1024];

fn main() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        if libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut()) != 0 {
            println!("sigaction FAIL");
            return;
        }
    }

    // ── Phase 1: mmap(PROT_READ) → store must fault (SEGV_ACCERR, si_addr) ──
    let p = mmap_anon(PAGE, libc::PROT_READ);
    arm(p as u64, PAGE);
    unsafe { std::ptr::write_volatile(p as *mut u64, 0x42) };
    report("mmapro_write", p as u64);
    // The handler made the page RW, so the re-run store landed.
    println!("mmapro_write_after={}", unsafe {
        std::ptr::read_volatile(p as *const u64) == 0x42
    });

    // ── Phase 2: RW page mprotect'd to PROT_READ → store faults; back to RW →
    // store succeeds ──
    let q = mmap_anon(PAGE, libc::PROT_READ | libc::PROT_WRITE);
    arm(q as u64, PAGE);
    unsafe { std::ptr::write_volatile(q as *mut u64, 7) };
    println!("mprotect_rw_precheck={}", !faulted());
    unsafe { libc::mprotect(q as *mut libc::c_void, PAGE, libc::PROT_READ) };
    arm(q as u64, PAGE);
    unsafe { std::ptr::write_volatile(q as *mut u64, 8) };
    report("mprotectro_write", q as u64);
    // Handler restored RW; an explicit mprotect back must also keep it writable.
    unsafe {
        libc::mprotect(
            q as *mut libc::c_void,
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
        )
    };
    arm(q as u64, PAGE);
    unsafe { std::ptr::write_volatile(q as *mut u64, 9) };
    println!("mprotect_rw_restore_ok={}", {
        !faulted() && unsafe { std::ptr::read_volatile(q as *const u64) == 9 }
    });

    // ── Phase 3: PROT_NONE → read faults; write faults (fresh page each) ──
    let n1 = mmap_anon(PAGE, libc::PROT_NONE);
    arm(n1 as u64, PAGE);
    let _ = unsafe { std::ptr::read_volatile(n1 as *const u64) };
    report("protnone_read", n1 as u64);
    let n2 = mmap_anon(PAGE, libc::PROT_NONE);
    arm(n2 as u64, PAGE);
    unsafe { std::ptr::write_volatile(n2 as *mut u64, 1) };
    report("protnone_write", n2 as u64);

    // ── Phase 3b: anon MAP_SHARED with PROT_READ → store must fault, and an
    // mprotect(RW) must make it writable (Go runtime/debug TestPanicOnFault's
    // exact shape: carrick's shared-anon aperture historically ignored the
    // mapping protection entirely, so the store silently succeeded). ──
    let s = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            PAGE,
            libc::PROT_READ,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if s == libc::MAP_FAILED {
        println!("mmap FAIL");
        unsafe { libc::_exit(2) };
    }
    let s = s as *mut u8;
    arm(s as u64, PAGE);
    unsafe { std::ptr::write_volatile(s as *mut u64, 0x53) };
    report("sharedro_write", s as u64);
    println!("sharedro_write_after={}", unsafe {
        std::ptr::read_volatile(s as *const u64) == 0x53
    });

    // ── Phase 4: the binary's own .rodata → store must fault (SEGV_ACCERR) ──
    // Pick the element at the middle of the 8 KiB array and fault on its page,
    // so the armed page is fully inside .rodata wherever the section starts.
    // Launder the address through black_box'd usize: this is a deliberate
    // store to immutable data (the probe's whole point), recovered by the
    // handler's mprotect.
    let ro_addr = std::hint::black_box(&RODATA[512] as *const u64 as usize);
    let ro = ro_addr as *mut u64;
    let ro_page = (ro_addr as u64) & !(PAGE as u64 - 1);
    arm(ro_page, PAGE);
    unsafe { std::ptr::write_volatile(ro, 1) };
    report("rodata_write", ro_addr as u64);

    println!("DONE");
}
