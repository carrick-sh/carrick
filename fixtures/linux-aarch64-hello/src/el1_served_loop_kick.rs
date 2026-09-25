//! Contract `kernel.vcpu.kick-el0-boundary` (Fact 9 of EL1 plan 1a): a kick
//! absorbed while a sibling is inside an EL1-served syscall must still stop
//! that sibling, so a stage-1 page-table drain — which kicks once and waits
//! for acknowledgement with no deadline (carrick-kernel `mm_quiesce.rs`) —
//! completes.
//!
//! The main thread runs `mmap`/first-touch/`munmap` cycles; each pauses the MM
//! and kicks the worker. `argv[1]` selects the worker's shape:
//!
//! - `loop`: the worker loops on EL1-served `lseek` with no other work.
//! - `burst`: the worker loops on served `lseek` while the main thread is
//!   between pause cycles, and computes in EL0 without a syscall while a
//!   cycle is open. A kick absorbed in the last `lseek` before a cycle opened
//!   therefore has no later syscall to surface it. A kick reaches the served
//!   path's post-check window only when the worker's host thread is stopped
//!   there (preempted or interrupted) as the drain kicks it, so this mode is
//!   run with the host CPUs oversubscribed.
//!
//! No runtime dependencies (the fixture build links no core/compiler_builtins):
//! single-writer counters use load/store, never fetch_add, and buffers are
//! written through raw pointers, never indexed.
#![no_main]
#![no_std]

#[path = "abi.rs"]
mod abi;

use abi::{syscall1, syscall2, syscall3, syscall4, syscall6};
use core::arch::{asm, global_asm};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const SYS_OPENAT: u64 = 56;
const SYS_LSEEK: u64 = 62;
const SYS_WRITE: u64 = 64;
const SYS_EXIT: u64 = 93;
const SYS_EXIT_GROUP: u64 = 94;
const SYS_CLOCK_GETTIME: u64 = 113;
const SYS_MUNMAP: u64 = 215;
const SYS_CLONE: u64 = 220;
const SYS_MMAP: u64 = 222;
const AT_FDCWD: u64 = (-100_i64) as u64;
const O_RDWR_CREAT_TRUNC: u64 = 0o2 | 0o100 | 0o1000;
const PROT_RW: u64 = 0x3;
const MAP_PRIVATE_ANON: u64 = 0x02 | 0x20;
// CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM
const CLONE_THREAD_FLAGS: u64 = 0x50f00;
const CLOCK_MONOTONIC: u64 = 1;
const STACK_SIZE: u64 = 64 * 1024;
const LOOP_CYCLES: u64 = 2_000;
const SPIN_LIMIT: u64 = 1 << 34;

const MODE_LOOP: u32 = 1;
const MODE_BURST: u32 = 2;
const BURST_CYCLES: u64 = 20_000;
/// Spin iterations between burst cycles, while the worker runs `lseek`.
const BURST_GAP: u64 = 100_000;

const RUNNING: u32 = 1;
const STOP: u32 = 2;
const STOPPED: u32 = 3;

struct Shared {
    fd: AtomicU64,
    mode: AtomicU32,
    state: AtomicU32,
    /// `burst`: a pause cycle is open. Written only by the main thread.
    open: AtomicU32,
    /// Written only by the worker thread.
    served: AtomicU64,
}

static SHARED: Shared = Shared {
    fd: AtomicU64::new(0),
    mode: AtomicU32::new(0),
    state: AtomicU32::new(0),
    open: AtomicU32::new(0),
    served: AtomicU64::new(0),
};
static PATH: [u8; 26] = *b"/tmp/el1_served_loop_kick\0";
static PREFIX: [u8; 24] = *b"served loop kick max_ns=";
static CYCLES_TAG: [u8; 8] = *b" cycles=";
static SERVED_TAG: [u8; 8] = *b" lseeks=";

global_asm!(
    r#"
    .global _start
    .type _start, %function
_start:
    mov x0, sp
    bl el1_served_loop_kick_main
"#
);

fn fail(code: u64) -> ! {
    unsafe {
        let _ = syscall1(SYS_EXIT_GROUP, code);
    }
    loop {
        core::hint::spin_loop();
    }
}

fn bump_served() {
    let served = SHARED.served.load(Ordering::Relaxed);
    SHARED.served.store(served + 1, Ordering::Release);
}

fn spin(iterations: u64) {
    let mut i = 0u64;
    while i < iterations {
        // Keep the loop: an opaque read the optimizer cannot fold.
        unsafe { asm!("", options(nomem, nostack, preserves_flags)) };
        i += 1;
    }
}

extern "C" fn worker() -> ! {
    let fd = SHARED.fd.load(Ordering::Acquire);
    let mode = SHARED.mode.load(Ordering::Acquire);
    SHARED.state.store(RUNNING, Ordering::Release);
    while SHARED.state.load(Ordering::Acquire) == RUNNING {
        if mode == MODE_BURST && SHARED.open.load(Ordering::Acquire) != 0 {
            core::hint::spin_loop();
            continue;
        }
        unsafe { syscall3(SYS_LSEEK, fd, 0, 0) };
        bump_served();
    }
    SHARED.state.store(STOPPED, Ordering::Release);
    unsafe { syscall1(SYS_EXIT, 0) };
    loop {
        core::hint::spin_loop();
    }
}

unsafe fn clone_thread(sp: u64) -> i64 {
    let ret: i64;
    let entry = worker as *const () as u64;
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
            entry = in(reg) entry,
            lateout("x0") ret,
            clobber_abi("C"),
        );
    }
    ret
}

fn now_ns() -> u64 {
    let mut ts = [0u64; 2];
    let p = ts.as_mut_ptr();
    unsafe {
        syscall2(SYS_CLOCK_GETTIME, CLOCK_MONOTONIC, p as u64);
        read_volatile(p) * 1_000_000_000 + read_volatile(p.add(1))
    }
}

fn spin_until(done: impl Fn() -> bool, code: u64) {
    let mut spins = 0u64;
    while !done() {
        spins += 1;
        if spins > SPIN_LIMIT {
            fail(code);
        }
        core::hint::spin_loop();
    }
}

unsafe fn put_bytes(out: *mut u8, len: &mut usize, bytes: *const u8, n: usize) {
    let mut i = 0usize;
    while i < n {
        unsafe { write_volatile(out.add(*len), read_volatile(bytes.add(i))) };
        *len += 1;
        i += 1;
    }
}

unsafe fn put_decimal(out: *mut u8, len: &mut usize, value: u64) {
    let mut digits = [0u8; 20];
    let tmp = digits.as_mut_ptr();
    let (mut n, mut v) = (0usize, value);
    loop {
        unsafe { write_volatile(tmp.add(n), b'0' + (v % 10) as u8) };
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    while n > 0 {
        n -= 1;
        unsafe { write_volatile(out.add(*len), read_volatile(tmp.add(n))) };
        *len += 1;
    }
}

fn print_line(slowest: u64, cycles: u64, served: u64) {
    let mut buf = [0u8; 128];
    let out = buf.as_mut_ptr();
    let mut len = 0usize;
    unsafe {
        put_bytes(out, &mut len, PREFIX.as_ptr(), PREFIX.len());
        put_decimal(out, &mut len, slowest);
        put_bytes(out, &mut len, CYCLES_TAG.as_ptr(), CYCLES_TAG.len());
        put_decimal(out, &mut len, cycles);
        put_bytes(out, &mut len, SERVED_TAG.as_ptr(), SERVED_TAG.len());
        put_decimal(out, &mut len, served);
        write_volatile(out.add(len), b'\n');
        len += 1;
        syscall3(SYS_WRITE, 1, out as u64, len as u64);
    }
}

/// `mmap`, first-touch write, `munmap`: each step pauses the MM.
fn pause_cycle() {
    unsafe {
        let page = syscall6(SYS_MMAP, 0, 0x4000, PROT_RW, MAP_PRIVATE_ANON, u64::MAX, 0);
        if page < 0 {
            fail(15);
        }
        write_volatile(page as *mut u64, 1);
        if syscall2(SYS_MUNMAP, page as u64, 0x4000) != 0 {
            fail(16);
        }
    }
}

/// `sp` is the initial process stack: argc, argv[0], argv[1], ...
#[unsafe(no_mangle)]
pub extern "C" fn el1_served_loop_kick_main(sp: *const u64) -> ! {
    unsafe {
        let argc = read_volatile(sp);
        let selector = if argc >= 2 {
            read_volatile(read_volatile(sp.add(2)) as *const u8)
        } else {
            b'l'
        };
        let mode = match selector {
            b'b' => MODE_BURST,
            _ => MODE_LOOP,
        };
        SHARED.mode.store(mode, Ordering::Release);
        let fd = syscall4(
            SYS_OPENAT,
            AT_FDCWD,
            PATH.as_ptr() as u64,
            O_RDWR_CREAT_TRUNC,
            0o600,
        );
        if fd < 0 {
            fail(10);
        }
        if syscall3(SYS_WRITE, fd as u64, PATH.as_ptr() as u64, 1) != 1 {
            fail(11);
        }
        SHARED.fd.store(fd as u64, Ordering::Release);
        let stack = syscall6(
            SYS_MMAP,
            0,
            STACK_SIZE,
            PROT_RW,
            MAP_PRIVATE_ANON,
            u64::MAX,
            0,
        );
        if stack < 0 {
            fail(12);
        }
        if clone_thread((stack as u64 + STACK_SIZE) & !0xf) < 0 {
            fail(13);
        }
        spin_until(|| SHARED.state.load(Ordering::Acquire) == RUNNING, 14);
        let mut slowest = 0u64;
        let cycles = match mode {
            MODE_LOOP => {
                spin_until(|| SHARED.served.load(Ordering::Acquire) >= 10_000, 14);
                LOOP_CYCLES
            }
            _ => BURST_CYCLES,
        };
        let mut cycle = 0u64;
        while cycle < cycles {
            if mode == MODE_BURST {
                spin(BURST_GAP);
                SHARED.open.store(1, Ordering::Release);
            }
            let start = now_ns();
            pause_cycle();
            let elapsed = now_ns() - start;
            if mode == MODE_BURST {
                SHARED.open.store(0, Ordering::Release);
            }
            if elapsed > slowest {
                slowest = elapsed;
            }
            cycle += 1;
        }
        SHARED.state.store(STOP, Ordering::Release);
        spin_until(|| SHARED.state.load(Ordering::Acquire) == STOPPED, 18);
        print_line(slowest, cycles, SHARED.served.load(Ordering::Acquire));
        syscall1(SYS_EXIT_GROUP, 0);
        fail(0);
    }
}
