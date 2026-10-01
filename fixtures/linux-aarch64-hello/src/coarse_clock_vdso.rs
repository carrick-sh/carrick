//! Contract `kernel.time.coarse-clock-vdso`: COARSE clock reads through the
//! vDSO, with no clock syscall of its own.
//!
//! Finds `__kernel_clock_gettime` and `__kernel_clock_getres` in the vDSO named
//! by `AT_SYSINFO_EHDR`, then reads `CLOCK_MONOTONIC_COARSE` and
//! `CLOCK_REALTIME_COARSE` `READS` times each through them, and asks their
//! resolution `READS` times each. MONOTONIC_COARSE must never go backwards.
//! Prints `coarse vdso loop ok`. The signed test counts the clock syscalls
//! the guest forwarded to the host while this ran.
//!
//! No runtime dependencies (the fixture build links no core).
#![no_main]
#![no_std]

#[path = "abi.rs"]
mod abi;

use abi::{SYS_WRITE, exit, syscall3};
use core::arch::global_asm;

const AT_NULL: u64 = 0;
const AT_SYSINFO_EHDR: u64 = 33;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const CLOCK_REALTIME_COARSE: u32 = 5;
const CLOCK_MONOTONIC_COARSE: u32 = 6;
const READS: u64 = 10_000;

static OK: [u8; 20] = *b"coarse vdso loop ok\n";

type ClockFn = unsafe extern "C" fn(u32, *mut [i64; 2]) -> i32;

global_asm!(
    r#"
    .global _start
    .type _start, %function
_start:
    mov x0, sp
    bl coarse_main
"#
);

unsafe fn read<T: Copy>(address: u64) -> T {
    unsafe { core::ptr::read_unaligned(address as *const T) }
}

unsafe fn name_is(address: u64, expected: &[u8]) -> bool {
    let mut i = 0;
    while i < expected.len() {
        if unsafe { read::<u8>(address + i as u64) } != expected[i] {
            return false;
        }
        i += 1;
    }
    unsafe { read::<u8>(address + expected.len() as u64) == 0 }
}

/// The auxv `AT_SYSINFO_EHDR` value from the initial process stack.
unsafe fn vdso_base(sp: u64) -> u64 {
    let argc: u64 = unsafe { read(sp) };
    // argv[argc] is NULL; envp follows and ends in NULL; auxv follows.
    let mut cursor = sp + 8 * (argc + 2);
    while unsafe { read::<u64>(cursor) } != 0 {
        cursor += 8;
    }
    cursor += 8;
    loop {
        let key: u64 = unsafe { read(cursor) };
        if key == AT_NULL {
            return 0;
        }
        if key == AT_SYSINFO_EHDR {
            return unsafe { read(cursor + 8) };
        }
        cursor += 16;
    }
}

unsafe fn vdso_symbol(base: u64, expected: &[u8]) -> u64 {
    let program_offset: u64 = unsafe { read(base + 0x20) };
    let program_size = u64::from(unsafe { read::<u16>(base + 0x36) });
    let program_count = u64::from(unsafe { read::<u16>(base + 0x38) });
    let mut dynamic = 0;
    let mut index = 0;
    while index < program_count {
        let header = base + program_offset + index * program_size;
        if unsafe { read::<u32>(header) } == PT_DYNAMIC {
            dynamic = base + unsafe { read::<u64>(header + 16) };
        }
        index += 1;
    }
    if dynamic == 0 {
        return 0;
    }
    let (mut symbols, mut strings, mut hash) = (0, 0, 0);
    loop {
        let tag: i64 = unsafe { read(dynamic) };
        let value: u64 = unsafe { read(dynamic + 8) };
        match tag {
            DT_SYMTAB => symbols = base + value,
            DT_STRTAB => strings = base + value,
            DT_HASH => hash = base + value,
            _ => {}
        }
        if tag == DT_NULL {
            break;
        }
        dynamic += 16;
    }
    if symbols == 0 || strings == 0 || hash == 0 {
        return 0;
    }
    let count = u64::from(unsafe { read::<u32>(hash + 4) });
    let mut index = 0;
    while index < count {
        let symbol = symbols + index * 24;
        let name = u64::from(unsafe { read::<u32>(symbol) });
        let section: u16 = unsafe { read(symbol + 6) };
        if name != 0 && section != 0 && unsafe { name_is(strings + name, expected) } {
            return base + unsafe { read::<u64>(symbol + 8) };
        }
        index += 1;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn coarse_main(sp: u64) -> ! {
    // SAFETY: the initial stack and the vDSO image are mapped by the loader;
    // the clock functions follow the Linux vDSO calling convention.
    unsafe {
        let base = vdso_base(sp);
        if base == 0 {
            exit(10);
        }
        let gettime = vdso_symbol(base, b"__kernel_clock_gettime");
        let getres = vdso_symbol(base, b"__kernel_clock_getres");
        if gettime == 0 || getres == 0 {
            exit(11);
        }
        let gettime: ClockFn = core::mem::transmute(gettime as usize);
        let getres: ClockFn = core::mem::transmute(getres as usize);
        let mut previous: u64 = 0;
        let mut value = [0i64; 2];
        let mut i = 0;
        while i < READS {
            if gettime(CLOCK_MONOTONIC_COARSE, &mut value) != 0 {
                exit(12);
            }
            let now = (value[0] as u64) * 1_000_000_000 + value[1] as u64;
            if now < previous {
                exit(13);
            }
            previous = now;
            if gettime(CLOCK_REALTIME_COARSE, &mut value) != 0 {
                exit(14);
            }
            if getres(CLOCK_MONOTONIC_COARSE, &mut value) != 0
                || getres(CLOCK_REALTIME_COARSE, &mut value) != 0
            {
                exit(15);
            }
            i += 1;
        }
        if syscall3(SYS_WRITE, 1, OK.as_ptr() as u64, OK.len() as u64) != OK.len() as i64 {
            exit(16);
        }
        exit(0)
    }
}
