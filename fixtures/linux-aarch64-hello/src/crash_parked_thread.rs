// Two threads: one parks forever in a private futex wait (EL1-parked under
// default CARRICK_EL1_SCHED/CARRICK_EL1_FUTEX) with a distinctive value
// pinned in a callee-saved register (x20) at the exact futex trap; the other
// reports the parked thread's tid, that resume PC, its worker-stack bounds
// and the marker over stdout, then crashes with SIGSEGV (a core-carrying
// signal) so the resulting core's `NT_PRSTATUS` notes can be checked against
// the report by an independent host-side reader
// (crates/carrick-embed/tests/crash_parked_thread.rs).
//
// The report is the only channel: the crash leaves no other way to hand the
// host dynamic (tid, resume-pc, stack address) values it could not have
// known ahead of time.
#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const SYS_WRITE: u64 = 64;
const SYS_EXIT: u64 = 93;
const SYS_EXIT_GROUP: u64 = 94;
const SYS_FUTEX: u64 = 98;
const SYS_SCHED_YIELD: u64 = 124;
const SYS_GETTID: u64 = 178;
const SYS_CLONE: u64 = 220;

const FUTEX_WAIT_PRIVATE: u64 = 128;
/// The futex word's fixed value: `FUTEX_WAIT_PRIVATE` blocks only while it
/// still holds this, so leaving it untouched (nobody ever wakes this thread)
/// parks it forever.
const FUTEX_EXPECTED: u32 = 1;

/// `CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM`
/// (the same flags `discard_fork_threads.rs` uses for a pthread-shaped
/// thread: one address space, one signal disposition table, joined at the
/// hip the way a crash-capture quorum expects a task's threads to be).
const CLONE_THREAD_FLAGS: u64 = 0x0005_0f00;

/// Written into `x20` at the exact instant the parked thread traps into
/// `futex(FUTEX_WAIT_PRIVATE)`. EL1's saved `ThreadCtx.x[20]` (and therefore
/// the resulting core's `NT_PRSTATUS.pr_reg[20]`) must read back exactly
/// this — the host test's positive identification of the parked thread,
/// independent of tid bookkeeping.
const MARKER: u64 = 0x5a5a_1eaf_c0de_babe;

const WORKER_STACK_SIZE: usize = 64 * 1024;

#[repr(C, align(16))]
struct WorkerStack([u8; WORKER_STACK_SIZE]);

static mut WORKER_STACK: WorkerStack = WorkerStack([0; WORKER_STACK_SIZE]);

static READY: AtomicU32 = AtomicU32::new(0);
static CHILD_TID: AtomicU64 = AtomicU64::new(0);
static RESUME_PC: AtomicU64 = AtomicU64::new(0);

/// The report's fixed 8-byte prefix, so the host side can find it in stdout
/// without any framing ambiguity.
const REPORT_MAGIC: [u8; 8] = *b"PARKTID:";
/// magic(8) + tid(8) + marker(8) + resume_pc(8) + stack_lo(8) + stack_hi(8).
const REPORT_LEN: usize = 48;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let stack_base = core::ptr::addr_of_mut!(WORKER_STACK) as u64;
        let stack_top = stack_base + WORKER_STACK_SIZE as u64 - 16;

        if clone_worker(stack_top) < 0 {
            exit(10);
        }

        // The worker publishes tid + resume-pc (a plain store) and THEN
        // `ready = 1` (a release store); this acquire load is the pairing
        // half, so both reads below are safe once it observes 1.
        while READY.load(Ordering::Acquire) == 0 {
            let _ = syscall0(SYS_SCHED_YIELD);
        }

        let tid = CHILD_TID.load(Ordering::Relaxed);
        let resume_pc = RESUME_PC.load(Ordering::Relaxed);
        if tid == 0 || resume_pc == 0 {
            exit(11);
        }

        write_report(
            tid,
            resume_pc,
            stack_base,
            stack_base + WORKER_STACK_SIZE as u64,
        );

        // A core-carrying fatal fault (SIGSEGV): a write through a null
        // pointer. The written value is irrelevant to the guest (it never
        // resumes); it is here only so a hex dump of the fault trivially
        // shows which fixture produced it.
        let bad = core::ptr::null_mut::<u64>();
        core::ptr::write_volatile(bad, MARKER);
        // Unreachable if the fault is delivered, which is the whole point.
        exit(200);
    }
}

/// The worker: publish this thread's tid, then park forever in a private
/// futex wait with `MARKER` pinned in `x20` at the trap, publishing the
/// resume PC and signalling readiness right before the first park.
unsafe extern "C" fn worker_entry() -> ! {
    unsafe {
        let tid = syscall0(SYS_GETTID);
        CHILD_TID.store(tid as u64, Ordering::Relaxed);
        let word_ptr = &FUTEX_WORD as *const AtomicU32 as u64;
        park_forever(word_ptr, MARKER, RESUME_PC.as_ptr(), READY.as_ptr());
    }
}

static FUTEX_WORD: AtomicU32 = AtomicU32::new(FUTEX_EXPECTED);

/// Compute and publish this call's resume PC (the instruction right after
/// `svc #0`, forward-referenced as local label `3`), publish `ready = 1`
/// (release), then loop forever: reload `marker` into `x20`, arm
/// `FUTEX_WAIT_PRIVATE` on `*word_ptr` against `FUTEX_EXPECTED`, and trap.
/// Nothing ever wakes this word, so the loop never makes progress past the
/// `svc` — the thread is EL1-parked for the rest of the run.
unsafe fn park_forever(word_ptr: u64, marker: u64, pc_slot: *mut u64, ready_slot: *mut u32) -> ! {
    unsafe {
        asm!(
            "adr {tmp}, 3f",
            "str {tmp}, [{pc_slot}]",
            "mov {tmp2:w}, #1",
            "stlr {tmp2:w}, [{ready_slot}]",
            "2:",
            "mov x20, {marker}",
            "mov x0, {word}",
            "mov x1, {op}",
            "mov x2, {expected}",
            "mov x3, #0",
            "mov x8, {sys_futex}",
            "svc #0",
            "3:",
            "b 2b",
            tmp = out(reg) _,
            tmp2 = out(reg) _,
            pc_slot = in(reg) pc_slot,
            ready_slot = in(reg) ready_slot,
            marker = in(reg) marker,
            word = in(reg) word_ptr,
            op = const FUTEX_WAIT_PRIVATE,
            expected = const FUTEX_EXPECTED,
            sys_futex = const SYS_FUTEX,
            out("x0") _,
            out("x1") _,
            out("x2") _,
            out("x3") _,
            out("x8") _,
            lateout("x20") _,
            options(nostack),
        );
    }
    // Unreachable: the asm above never falls out of its own `2:`/`svc`/`3:`/
    // `b 2b` loop (nothing ever wakes `FUTEX_WORD`). This satisfies `-> !`
    // without an `options(noreturn)` asm block, which disallows outputs.
    loop {}
}

unsafe fn clone_worker(sp: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "mov x0, {flags}",
            "mov x1, {sp}",
            "mov x2, #0",
            "mov x3, #0",
            "mov x4, #0",
            "mov x8, {sys_clone}",
            "svc #0",
            "cmp x0, #0",
            "b.ne 1f",
            "blr {entry}",
            "1:",
            flags = in(reg) CLONE_THREAD_FLAGS,
            sp = in(reg) sp,
            sys_clone = const SYS_CLONE,
            entry = in(reg) worker_entry as unsafe extern "C" fn() -> ! as *const () as u64,
            lateout("x0") ret,
            clobber_abi("C"),
        );
    }
    ret
}

/// Write `bytes` at `buf[at..at + N]` with plain, per-byte assignments
/// through constant indices: no_std has no `#[panic_handler]`-free path
/// through `<[T]>::copy_from_slice`'s length-mismatch check (its cold arm
/// still needs a linkable symbol), and every index here is a compile-time
/// constant the optimizer proves in range, so there is no bounds-check panic
/// path to link at all.
fn place<const N: usize>(buf: &mut [u8; REPORT_LEN], at: usize, bytes: [u8; N]) {
    let mut i = 0;
    while i < N {
        buf[at + i] = bytes[i];
        i += 1;
    }
}

unsafe fn write_report(tid: u64, resume_pc: u64, stack_lo: u64, stack_hi: u64) {
    let mut buf = [0u8; REPORT_LEN];
    place(&mut buf, 0, REPORT_MAGIC);
    place(&mut buf, 8, tid.to_le_bytes());
    place(&mut buf, 16, MARKER.to_le_bytes());
    place(&mut buf, 24, resume_pc.to_le_bytes());
    place(&mut buf, 32, stack_lo.to_le_bytes());
    place(&mut buf, 40, stack_hi.to_le_bytes());
    unsafe {
        if syscall3(SYS_WRITE, 1, buf.as_ptr() as u64, REPORT_LEN as u64) != REPORT_LEN as i64 {
            exit(12);
        }
    }
}

unsafe fn syscall0(number: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "svc #0",
            inlateout("x0") 0i64 => ret,
            in("x8") number,
            options(nostack)
        );
    }
    ret
}

unsafe fn syscall3(number: u64, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "svc #0",
            inlateout("x0") arg0 as i64 => ret,
            in("x1") arg1,
            in("x2") arg2,
            in("x8") number,
            options(nostack)
        );
    }
    ret
}

fn exit(code: u64) -> ! {
    unsafe {
        let _ = syscall1(SYS_EXIT_GROUP, code);
        let _ = syscall1(SYS_EXIT, code);
    }
    loop {}
}

unsafe fn syscall1(number: u64, arg0: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "svc #0",
            inlateout("x0") arg0 as i64 => ret,
            in("x8") number,
            options(nostack)
        );
    }
    ret
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}
