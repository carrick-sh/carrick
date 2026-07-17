//! Compare Carrick's guest vDSO clock directly with the raw clock syscall.
//! The vDSO call exercises the translated `CNTVCT_EL0` path; the raw syscall
//! crosses Carrick's dispatcher. Each vDSO result must lie between two syscall
//! reads from the same clock, allowing only a small scheduling/conversion
//! margin rather than any suspend-sized divergence.

use std::ptr;

const AT_SYSINFO_EHDR: u64 = 33;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const SLACK_NS: i128 = 1_000_000;

unsafe fn read_u16(address: u64) -> u16 {
    ptr::read_unaligned(address as *const u16)
}

unsafe fn read_u32(address: u64) -> u32 {
    ptr::read_unaligned(address as *const u32)
}

unsafe fn read_u64(address: u64) -> u64 {
    ptr::read_unaligned(address as *const u64)
}

unsafe fn read_i64(address: u64) -> i64 {
    ptr::read_unaligned(address as *const i64)
}

unsafe fn c_string_equals(address: u64, expected: &str) -> bool {
    for (index, byte) in expected.as_bytes().iter().copied().enumerate() {
        if *((address + index as u64) as *const u8) != byte {
            return false;
        }
    }
    *((address + expected.len() as u64) as *const u8) == 0
}

unsafe fn vdso_symbol(expected: &str) -> u64 {
    let base = libc::getauxval(AT_SYSINFO_EHDR);
    if base == 0 {
        return 0;
    }

    let program_offset = read_u64(base + 0x20);
    let program_size = u64::from(read_u16(base + 0x36));
    let program_count = u64::from(read_u16(base + 0x38));
    let mut dynamic = 0;
    for index in 0..program_count {
        let header = base + program_offset + index * program_size;
        if read_u32(header) == PT_DYNAMIC {
            dynamic = base + read_u64(header + 16);
        }
    }
    if dynamic == 0 {
        return 0;
    }

    let (mut symbols, mut strings, mut hash) = (0, 0, 0);
    loop {
        let tag = read_i64(dynamic);
        let value = read_u64(dynamic + 8);
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

    let symbol_count = u64::from(read_u32(hash + 4));
    for index in 0..symbol_count {
        let symbol = symbols + index * 24;
        let name = u64::from(read_u32(symbol));
        let section = read_u16(symbol + 6);
        if name != 0 && section != 0 && c_string_equals(strings + name, expected) {
            return base + read_u64(symbol + 8);
        }
    }
    0
}

type ClockGettime = unsafe extern "C" fn(libc::clockid_t, *mut libc::timespec) -> libc::c_int;

fn nanoseconds(value: libc::timespec) -> i128 {
    i128::from(value.tv_sec) * 1_000_000_000 + i128::from(value.tv_nsec)
}

unsafe fn clock_is_coherent(function: ClockGettime, clock: libc::clockid_t) -> bool {
    let mut before = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut observed = before;
    let mut after = before;
    let before_rc = libc::syscall(libc::SYS_clock_gettime, clock, &mut before);
    let vdso_rc = function(clock, &mut observed);
    let after_rc = libc::syscall(libc::SYS_clock_gettime, clock, &mut after);
    if before_rc != 0 || vdso_rc != 0 || after_rc != 0 {
        return false;
    }
    let before = nanoseconds(before);
    let observed = nanoseconds(observed);
    let after = nanoseconds(after);
    before - SLACK_NS <= observed && observed <= after + SLACK_NS
}

fn main() {
    unsafe {
        let address = vdso_symbol("__kernel_clock_gettime");
        println!("vdso_clock_gettime_resolved={}", address != 0);
        if address == 0 {
            println!("monotonic_vdso_syscall_coherent=false");
            println!("realtime_vdso_syscall_coherent=false");
            std::process::exit(1);
        }
        let function: ClockGettime = std::mem::transmute(address);
        let monotonic = clock_is_coherent(function, libc::CLOCK_MONOTONIC);
        let realtime = clock_is_coherent(function, libc::CLOCK_REALTIME);
        println!("monotonic_vdso_syscall_coherent={monotonic}");
        println!("realtime_vdso_syscall_coherent={realtime}");
        if !monotonic || !realtime {
            std::process::exit(1);
        }
    }
}
