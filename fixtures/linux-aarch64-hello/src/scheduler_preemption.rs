// Multi-worker syscall-free compute loop and preemption test fixture.
//
// Spawns worker tasks that run in a pure compute loop (no syscalls),
// updating a shared progress counter and polling a shared stop flag.
// A controller task monitors all workers and asserts that every worker
// makes observable progress under Carrick's preemption scheduler before
// signalling the stop flag.
//
// Exit code 0 iff all workers make progress without deadlocking or starving.

#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 64;
const SYS_EXIT: u64 = 93;
const SYS_EXIT_GROUP: u64 = 94;
const SYS_SCHED_YIELD: u64 = 124;
const SYS_CLONE: u64 = 220;
const SYS_MMAP: u64 = 222;

const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const MAP_SHARED: u64 = 0x01;
const MAP_ANONYMOUS: u64 = 0x20;

// Clone flags for creating a thread:
// CLONE_VM (0x100) | CLONE_FS (0x200) | CLONE_FILES (0x400) |
// CLONE_SIGHAND (0x800) | CLONE_THREAD (0x10000) | CLONE_SYSVSEM (0x40000)
const CLONE_THREAD_FLAGS: u64 = 0x50f00;

const MAX_WORKERS: usize = 128;
const DEFAULT_WORKERS: usize = 4;
const STACK_SIZE: usize = 16384;

#[repr(C, align(64))]
struct SharedControl {
    stop: u32,
    ready_workers: u32,
    finished_workers: u32,
    _reserved: u32,
    progress: [u32; MAX_WORKERS],
}

static OK_MSG: [u8; 14] = *b"preemption ok\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        // Map one shared-anon page for inter-task coordination
        let mapped = syscall6(
            SYS_MMAP,
            0,
            core::mem::size_of::<SharedControl>() as u64,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS,
            (-1_i64) as u64,
            0,
        );
        if mapped <= 0 {
            exit(10);
        }

        let ctrl = mapped as *mut SharedControl;
        atomic_store(core::ptr::addr_of!((*ctrl).stop), 0);
        atomic_store(core::ptr::addr_of!((*ctrl).ready_workers), 0);
        atomic_store(core::ptr::addr_of!((*ctrl).finished_workers), 0);

        for i in 0..MAX_WORKERS {
            let prog_ptr = core::ptr::addr_of!((*ctrl).progress).cast::<u32>().add(i);
            atomic_store(prog_ptr, 0);
        }

        let num_workers = DEFAULT_WORKERS;

        // Allocate stacks for each worker thread
        let stacks_len = (num_workers * STACK_SIZE) as u64;
        let stacks_map = syscall6(
            SYS_MMAP,
            0,
            stacks_len,
            PROT_READ | PROT_WRITE,
            0x02 | MAP_ANONYMOUS, // MAP_PRIVATE | MAP_ANONYMOUS
            (-1_i64) as u64,
            0,
        );
        if stacks_map <= 0 {
            exit(11);
        }

        for i in 0..num_workers {
            let stack_top = (stacks_map as u64) + ((i + 1) * STACK_SIZE) as u64;
            // Align stack to 16 bytes
            let child_sp = stack_top & !0xf;

            // Spawn worker thread via clone
            let tid = clone_thread(child_sp, ctrl, i);
            if tid < 0 {
                exit(12);
            }
        }

        // Controller loop: wait for all workers to be ready
        let mut attempts = 0;
        let ready_ptr = core::ptr::addr_of!((*ctrl).ready_workers);
        while atomic_load(ready_ptr) < num_workers as u32 {
            syscall0(SYS_SCHED_YIELD);
            attempts += 1;
            if attempts > 100_000 {
                exit(13); // Workers timed out starting
            }
        }

        // Controller verifies every worker makes progress in its pure compute loop
        attempts = 0;
        loop {
            let mut all_progressed = true;
            for i in 0..num_workers {
                let prog_ptr = core::ptr::addr_of!((*ctrl).progress).cast::<u32>().add(i);
                if atomic_load(prog_ptr) < 1 {
                    all_progressed = false;
                    break;
                }
            }
            if all_progressed {
                break;
            }
            syscall0(SYS_SCHED_YIELD);
            attempts += 1;
            if attempts > 200_000 {
                exit(14); // Worker starvation: preemption failed to rotate
            }
        }

        // Signal workers to stop
        atomic_store(core::ptr::addr_of!((*ctrl).stop), 1);

        // Wait for all workers to finish
        attempts = 0;
        let fin_ptr = core::ptr::addr_of!((*ctrl).finished_workers);
        while atomic_load(fin_ptr) < num_workers as u32 {
            syscall0(SYS_SCHED_YIELD);
            attempts += 1;
            if attempts > 100_000 {
                exit(15); // Workers failed to exit cleanly
            }
        }

        // All workers completed: emit success message
        let wrote = syscall3(
            SYS_WRITE,
            1,
            OK_MSG.as_ptr() as u64,
            OK_MSG.len() as u64,
        );
        if wrote != OK_MSG.len() as i64 {
            exit(16);
        }

        exit(0);
    }
}

/// Trampoline for worker threads
unsafe extern "C" fn worker_entry(ctrl: *mut SharedControl, index: usize) -> ! {
    unsafe {
        let ready_ptr = core::ptr::addr_of!((*ctrl).ready_workers);
        atomic_add(ready_ptr, 1);

        let stop_ptr = core::ptr::addr_of!((*ctrl).stop);
        let prog_ptr = core::ptr::addr_of!((*ctrl).progress).cast::<u32>().add(index);

        // Pure compute loop without any syscalls:
        // Rotates, updates progress counter, spins.
        let mut step = 0u32;
        while atomic_load(stop_ptr) == 0 {
            step = step.wrapping_add(1);
            if (step & 0x7ff) == 0 {
                atomic_add(prog_ptr, 1);
            }
            core::hint::spin_loop();
        }

        let fin_ptr = core::ptr::addr_of!((*ctrl).finished_workers);
        atomic_add(fin_ptr, 1);
        let _ = syscall1(SYS_EXIT, 0);
    }
    loop {}
}

/// Spawns a thread using clone(CLONE_THREAD_FLAGS, sp)
unsafe fn clone_thread(sp: u64, ctrl: *mut SharedControl, index: usize) -> i64 {
    let ret: i64;
    let ctrl_ptr = ctrl as u64;
    let index_val = index as u64;
    let fn_ptr = worker_entry as *const () as u64;

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
            // Child:
            "mov x0, {ctrl}",
            "mov x1, {idx}",
            "blr {entry}",
            "1:",
            flags = in(reg) CLONE_THREAD_FLAGS,
            sp = in(reg) sp,
            sys_clone = const SYS_CLONE,
            ctrl = in(reg) ctrl_ptr,
            idx = in(reg) index_val,
            entry = in(reg) fn_ptr,
            lateout("x0") ret,
            clobber_abi("C"),
        );
    }
    ret
}

unsafe fn atomic_add(ptr: *const u32, val: u32) -> u32 {
    let prev: u32;
    unsafe {
        asm!(
            "1:",
            "ldaxr {prev:w}, [{ptr}]",
            "add {tmp:w}, {prev:w}, {val:w}",
            "stlxr {res:w}, {tmp:w}, [{ptr}]",
            "cbnz {res:w}, 1b",
            ptr = in(reg) ptr,
            val = in(reg) val,
            prev = out(reg) prev,
            tmp = out(reg) _,
            res = out(reg) _,
            options(nostack)
        );
    }
    prev
}

unsafe fn atomic_load(ptr: *const u32) -> u32 {
    let val: u32;
    unsafe {
        asm!(
            "ldar {val:w}, [{ptr}]",
            ptr = in(reg) ptr,
            val = out(reg) val,
            options(nostack, readonly)
        );
    }
    val
}

unsafe fn atomic_store(ptr: *const u32, val: u32) {
    unsafe {
        asm!(
            "stlr {val:w}, [{ptr}]",
            ptr = in(reg) ptr,
            val = in(reg) val,
            options(nostack)
        );
    }
}

unsafe fn syscall0(number: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "svc #0",
            lateout("x0") ret,
            in("x8") number,
            options(nostack)
        );
    }
    ret
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
        asm!(
            "svc #0",
            inlateout("x0") arg0 as i64 => ret,
            in("x1") arg1,
            in("x2") arg2,
            in("x3") arg3,
            in("x4") arg4,
            in("x5") arg5,
            in("x8") number,
            options(nostack)
        );
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
