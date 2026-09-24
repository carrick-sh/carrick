// Repeated thread-stack MADV_DONTNEED across fork(2) while threads are alive.
//
// This mirrors glibc's pthread stack lifecycle under CPython's
// `test.fork_wait` (cpython-fork1 / cpython-wait4): each thread stack is a
// PROT_NONE mapping with a 4 KiB guard page whose remainder is mprotect'ed
// read/write; the stack is cached and reused by the next thread; the main
// thread forks while the threads are alive; an exiting thread discards the
// unused part of its own stack with MADV_DONTNEED (glibc's
// `advise_stack_range`), a range that starts one page above the mapping and
// is therefore not aligned to a 16 KiB host page.
//
// Every round forks while all threads run, then:
//   1. the CHILD discards every stack range and checks its own view;
//   2. every parent thread discards its own stack range and exits, while the
//      child is still alive and holding the COW-shared frames;
//   3. the child re-checks its view (the parent's discard must not reach it)
//      and exits; the parent checks its own view and reaps the child.
// The first round writes every page of every stack; later rounds touch only
// the top of the stack, exactly like a reused glibc stack, so the discarded
// range's edge pages are never re-touched between two discards.
//
// Linux semantics (man 2 madvise, man 2 fork): a private anonymous
// MADV_DONTNEED range reads back as zero-fill in the calling process only;
// bytes outside the range are preserved; the other process's copy is
// unaffected. exit_group(0) and "discard fork threads ok" iff every check
// holds in both processes.

#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 64;
const SYS_EXIT: u64 = 93;
const SYS_EXIT_GROUP: u64 = 94;
const SYS_SCHED_YIELD: u64 = 124;
const SYS_MUNMAP: u64 = 215;
const SYS_CLONE: u64 = 220;
const SYS_MMAP: u64 = 222;
const SYS_MPROTECT: u64 = 226;
const SYS_MADVISE: u64 = 233;
const SYS_WAIT4: u64 = 260;

const PROT_NONE: u64 = 0;
const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_STACK: u64 = 0x20000;
const MADV_DONTNEED: u64 = 4;
const SIGCHLD: u64 = 17;
const CLONE_THREAD_FLAGS: u64 = 0x50f00;

const PAGE: u64 = 4096;
const HOST_PAGE: u64 = 16384;
const THREADS: usize = 4;
const ROUNDS: u32 = 3;
const STACK_SIZE: u64 = 8 * 1024 * 1024;
const GUARD: u64 = PAGE;
/// glibc's discard length for an 8 MiB stack in cpython-fork1's crash.
const DISCARD_LEN: u64 = 0x7de000;
/// Top-of-stack bytes a reused stack's thread touches (well above the range).
const TOP_TOUCH: u64 = 64 * 1024;
const SPIN_LIMIT: u32 = 20_000_000;

#[repr(C, align(64))]
struct Control {
    ready: u32,
    go_exit: u32,
    exited: u32,
    child_discarded: u32,
    parent_discarded: u32,
    round: u32,
    stacks: [u64; THREADS],
}

static OK_MSG: [u8; 24] = *b"discard fork threads ok\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let ctrl = syscall6(
            SYS_MMAP,
            0,
            PAGE,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS,
            u64::MAX,
            0,
        );
        if ctrl <= 0 {
            exit(10);
        }
        let ctrl = ctrl as *mut Control;
        for i in 0..THREADS {
            // glibc allocate_stack: PROT_NONE mapping, guard at the bottom,
            // the rest mprotect'ed read/write.
            let mem = syscall6(
                SYS_MMAP,
                0,
                STACK_SIZE,
                PROT_NONE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
                u64::MAX,
                0,
            );
            if mem <= 0 {
                exit(11);
            }
            let mem = mem as u64;
            if syscall3(
                SYS_MPROTECT,
                mem + GUARD,
                STACK_SIZE - GUARD,
                PROT_READ | PROT_WRITE,
            ) != 0
            {
                exit(12);
            }
            set_stack(ctrl, i, mem);
        }

        for round in 0..ROUNDS {
            store(&raw const (*ctrl).ready, 0);
            store(&raw const (*ctrl).go_exit, 0);
            store(&raw const (*ctrl).exited, 0);
            store(&raw const (*ctrl).child_discarded, 0);
            store(&raw const (*ctrl).parent_discarded, 0);
            store(&raw const (*ctrl).round, round);
            for i in 0..THREADS {
                let top = (stack(ctrl, i) + STACK_SIZE - 256) & !0xf;
                if clone_thread(top, ctrl, i) < 0 {
                    exit(13);
                }
            }
            wait_for(&raw const (*ctrl).ready, THREADS as u32, 14);

            // Fork while every thread is alive and its stack is populated.
            let pid = syscall6(SYS_CLONE, SIGCHLD, 0, 0, 0, 0, 0);
            if pid < 0 {
                exit(15);
            }
            if pid == 0 {
                child(ctrl, round);
            }

            // The child discards first; then the parent's threads discard
            // their own stacks while the child still maps the shared frames.
            wait_for(&raw const (*ctrl).child_discarded, 1, 16);
            store(&raw const (*ctrl).go_exit, 1);
            wait_for(&raw const (*ctrl).exited, THREADS as u32, 17);
            store(&raw const (*ctrl).parent_discarded, 1);

            let mut status: i32 = 0;
            if syscall6(SYS_WAIT4, pid as u64, (&raw mut status) as u64, 0, 0, 0, 0) != pid {
                exit(18);
            }
            if status != 0 {
                // Child exit code lands in bits 8..16; report it distinctly.
                exit(100 + ((status as u64 >> 8) & 0x3f));
            }
            for i in 0..THREADS {
                if !stack_view_ok(stack(ctrl, i), round, round + 1 == ROUNDS) {
                    exit(19);
                }
            }
        }
        for i in 0..THREADS {
            let _ = syscall3(SYS_MUNMAP, stack(ctrl, i), STACK_SIZE, 0);
        }
        let len = OK_MSG.len() as u64;
        if syscall3(SYS_WRITE, 1, OK_MSG.as_ptr() as u64, len) != len as i64 {
            exit(20);
        }
        exit(0);
    }
}

unsafe fn child(ctrl: *mut Control, round: u32) -> ! {
    unsafe {
        for i in 0..THREADS {
            let mem = stack(ctrl, i);
            if syscall3(SYS_MADVISE, mem + GUARD, DISCARD_LEN, MADV_DONTNEED) != 0 {
                exit(30);
            }
            if !stack_view_ok(mem, round, true) {
                exit(31);
            }
        }
        store(&raw const (*ctrl).child_discarded, 1);
        // Stay alive, holding the shared frames, until the parent's threads
        // have discarded their own copies.
        wait_for(&raw const (*ctrl).parent_discarded, 1, 32);
        for i in 0..THREADS {
            if !stack_view_ok(stack(ctrl, i), round, true) {
                exit(33);
            }
        }
        exit(0);
    }
}

/// Check one process's view of a discarded stack: the discarded range is
/// zero-filled and the surviving top of the stack still holds this round's
/// marker. `edges` also reads the pages within one host page of either end
/// of the range; the parent leaves those untouched until the last round so a
/// reused stack's discard edges stay exactly as the previous discard left them.
unsafe fn stack_view_ok(mem: u64, round: u32, edges: bool) -> bool {
    let start = mem + GUARD;
    let end = start + DISCARD_LEN;
    let mut page = start;
    while page < end {
        let near_edge = page < start + HOST_PAGE || page + HOST_PAGE > end;
        if (edges || !near_edge) && unsafe { core::ptr::read_volatile(page as *const u64) } != 0 {
            return false;
        }
        page += PAGE;
    }
    let mut page = mem + STACK_SIZE - TOP_TOUCH;
    while page < mem + STACK_SIZE {
        if unsafe { core::ptr::read_volatile(page as *const u64) } != marker(round) {
            return false;
        }
        page += PAGE;
    }
    true
}

/// Indexed without a bounds check: a no_std fixture has no panic runtime.
unsafe fn stack(ctrl: *mut Control, index: usize) -> u64 {
    unsafe { *(&raw const (*ctrl).stacks).cast::<u64>().add(index) }
}

unsafe fn set_stack(ctrl: *mut Control, index: usize, mem: u64) {
    unsafe { *(&raw mut (*ctrl).stacks).cast::<u64>().add(index) = mem }
}

fn marker(round: u32) -> u64 {
    0x5a5a_0000_0000_0000 | u64::from(round + 1)
}

unsafe extern "C" fn thread_entry(ctrl: *mut Control, index: usize) -> ! {
    unsafe {
        let mem = stack(ctrl, index);
        let round = load(&raw const (*ctrl).round);
        // A fresh stack is populated throughout (a deep call chain); a reused
        // one only near its top. The thread's own frame lives in the top
        // 256 bytes, above every page written here.
        let low = if round == 0 {
            mem + GUARD
        } else {
            mem + STACK_SIZE - TOP_TOUCH
        };
        let mut page = low;
        while page < mem + STACK_SIZE - PAGE {
            core::ptr::write_volatile(page as *mut u64, marker(round));
            page += PAGE;
        }
        core::ptr::write_volatile(page as *mut u64, marker(round));
        add(&raw const (*ctrl).ready, 1);
        wait_for(&raw const (*ctrl).go_exit, 1, 40);
        // glibc advise_stack_range: discard the unused stack below sp.
        if syscall3(SYS_MADVISE, mem + GUARD, DISCARD_LEN, MADV_DONTNEED) != 0 {
            exit(41);
        }
        add(&raw const (*ctrl).exited, 1);
        let _ = syscall1(SYS_EXIT, 0);
    }
    loop {}
}

unsafe fn clone_thread(sp: u64, ctrl: *mut Control, index: usize) -> i64 {
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
            "mov x0, {ctrl}",
            "mov x1, {idx}",
            "blr {entry}",
            "1:",
            flags = in(reg) CLONE_THREAD_FLAGS,
            sp = in(reg) sp,
            sys_clone = const SYS_CLONE,
            ctrl = in(reg) ctrl as u64,
            idx = in(reg) index as u64,
            entry = in(reg) thread_entry as *const () as u64,
            lateout("x0") ret,
            clobber_abi("C"),
        );
    }
    ret
}

unsafe fn wait_for(ptr: *const u32, value: u32, code: u64) {
    let mut spins = 0u32;
    while unsafe { load(ptr) } < value {
        unsafe {
            syscall0(SYS_SCHED_YIELD);
        }
        spins += 1;
        if spins > SPIN_LIMIT {
            exit(code);
        }
    }
}

unsafe fn add(ptr: *const u32, val: u32) {
    unsafe {
        asm!(
            "1:",
            "ldaxr {prev:w}, [{ptr}]",
            "add {prev:w}, {prev:w}, {val:w}",
            "stlxr {res:w}, {prev:w}, [{ptr}]",
            "cbnz {res:w}, 1b",
            ptr = in(reg) ptr,
            val = in(reg) val,
            prev = out(reg) _,
            res = out(reg) _,
            options(nostack)
        );
    }
}

unsafe fn load(ptr: *const u32) -> u32 {
    let val: u32;
    unsafe {
        asm!("ldar {val:w}, [{ptr}]", ptr = in(reg) ptr, val = out(reg) val, options(nostack, readonly));
    }
    val
}

unsafe fn store(ptr: *const u32, val: u32) {
    unsafe {
        asm!("stlr {val:w}, [{ptr}]", ptr = in(reg) ptr, val = in(reg) val, options(nostack));
    }
}

unsafe fn syscall0(number: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!("svc #0", lateout("x0") ret, in("x8") number, options(nostack));
    }
    ret
}

unsafe fn syscall1(number: u64, arg0: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!("svc #0", inlateout("x0") arg0 as i64 => ret, in("x8") number, options(nostack));
    }
    ret
}

unsafe fn syscall3(number: u64, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!("svc #0", inlateout("x0") arg0 as i64 => ret, in("x1") arg1, in("x2") arg2, in("x8") number, options(nostack));
    }
    ret
}

unsafe fn syscall6(
    number: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> i64 {
    let ret: i64;
    unsafe {
        asm!("svc #0", inlateout("x0") arg0 as i64 => ret, in("x1") arg1, in("x2") arg2, in("x3") arg3, in("x4") arg4, in("x5") arg5, in("x8") number, options(nostack));
    }
    ret
}

fn exit(code: u64) -> ! {
    unsafe {
        let _ = syscall1(SYS_EXIT_GROUP, code);
    }
    loop {}
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    exit(99)
}
